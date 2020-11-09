package router

// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/anomalousiam"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/badip"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/sshbruteforce"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/computeinstancescanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/containerscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/datasetscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/firewallscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/iamscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/loggingscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/sqlscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/storagescanner"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

var findings = []Namer{
	&anomalousiam.Finding{},
	&badip.Finding{},
	&sshbruteforce.Finding{},
	&storagescanner.Finding{},
	&sqlscanner.Finding{},
	&containerscanner.Finding{},
	&computeinstancescanner.Finding{},
	&firewallscanner.Finding{},
	&datasetscanner.Finding{},
	&loggingscanner.Finding{},
	&iamscanner.Finding{},
}

// originalEventTime is the security mark key name used to hold the finding's event time.
const originalEventTime = "sra-remediated-event-time"
const configPath = "./serverless_function_source_code/config/sra.yaml"

// Namer represents findings that export their name.
type Namer interface {
	Name([]byte) string
}

// Services contains the services needed for this function.
type Services struct {
	PubSub                *services.PubSub
	Configuration         *Configuration
	Logger                *services.Logger
	Resource              *services.Resource
	SecurityCommandCenter *services.CommandCenter
}

// Values contains the required values for this function.
type Values struct {
	Finding []byte
}

// topics maps automation targets to PubSub topics.
var topics = map[string]struct{ Topic string }{
	"gce_create_disk_snapshot":  {Topic: "threat-findings-create-disk-snapshot"},
	"iam_revoke":                {Topic: "threat-findings-iam-revoke"},
	"close_bucket":              {Topic: "threat-findings-close-bucket"},
	"enable_bucket_only_policy": {Topic: "threat-findings-enable-bucket-only-policy"},
	"close_cloud_sql":           {Topic: "threat-findings-remove-public-sql"},
	"cloud_sql_require_ssl":     {Topic: "threat-findings-require-ssl"},
	"cloud_sql_update_password": {Topic: "threat-findings-update-password"},
	"disable_dashboard":         {Topic: "threat-findings-disable-dashboard"},
	"remove_public_ip":          {Topic: "threat-findings-remove-public-ip"},
	"remediate_firewall":        {Topic: "threat-findings-open-firewall"},
	"close_public_dataset":      {Topic: "threat-findings-close-public-dataset"},
	"enable_audit_logs":         {Topic: "threat-findings-enable-audit-logs"},
	"remove_non_org_members":    {Topic: "threat-findings-remove-non-org-members"},
}

// Automation represents configuration for an automation.
type Automation struct {
	Action     string
	Target     []string
	Exclude    []string
	Properties struct {
		DryRun    bool `yaml:"dry_run"`
		RevokeIAM struct {
			AllowDomains []string `yaml:"allow_domains"`
		} `yaml:"revoke_iam"`
		CreateSnapshot struct {
			TargetSnapshotProjectID string `yaml:"target_snapshot_project_id"`
			TargetSnapshotZone      string `yaml:"target_snapshot_zone"`
			Output                  []string
			Turbinia                struct {
				ProjectID string
				Topic     string
				Zone      string
			}
		} `yaml:"gce_create_snapshot"`
		OpenFirewall struct {
			SourceRanges      []string `yaml:"source_ranges"`
			RemediationAction string   `yaml:"remediation_action"`
		} `yaml:"open_firewall"`
		NonOrgMembers struct {
			AllowDomains []string `yaml:"allow_domains"`
		} `yaml:"non_org_members"`
	}
}

// Configuration maps findings to automations.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Name       string
		Parameters struct {
			ETD struct {
				BadIP         []Automation `yaml:"bad_ip"`
				AnomalousIAM  []Automation `yaml:"anomalous_iam"`
				SSHBruteForce []Automation `yaml:"ssh_brute_force"`
			}
			SHA struct {
				PublicBucketACL         []Automation `yaml:"public_bucket_acl"`
				BucketPolicyOnlyDisable []Automation `yaml:"bucket_policy_only_disabled"`
				PublicSQLInstance       []Automation `yaml:"public_sql_instance"`
				SSLNotEnforced          []Automation `yaml:"ssl_not_enforced"`
				SQLNoRootPassword       []Automation `yaml:"sql_no_root_password"`
				PublicIPAddress         []Automation `yaml:"public_ip_address"`
				OpenFirewall            []Automation `yaml:"open_firewall"`
				PublicDataset           []Automation `yaml:"bigquery_public_dataset"`
				AuditLoggingDisabled    []Automation `yaml:"audit_logging_disabled"`
				WebUIEnabled            []Automation `yaml:"web_ui_enabled"`
				NonOrgMembers           []Automation `yaml:"non_org_members"`
			}
		}
	}
}

// Config will return the router's configuration.
func Config() (*Configuration, error) {
	var c Configuration
	b, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal config.yaml")
	}
	return &c, nil
}

// ruleName will attempt to deserialize all findings until a name is extracted.
func ruleName(b []byte) string {
	for _, finding := range findings {
		if n := finding.Name(b); n != "" {
			return n
		}
	}
	return ""
}

func markAsRemediated(ctx context.Context, name, eventTime string, services *Services) error {
	m := map[string]string{"sra-remediated-event-time": eventTime}
	if _, err := services.SecurityCommandCenter.AddSecurityMarks(ctx, name, m); err != nil {
		return err
	}
	return nil
}

// Execute will route the incoming finding to the appropriate remediations.
func Execute(ctx context.Context, values *Values, services *Services) error {
	switch name := ruleName(values.Finding); name {
	case "bad_ip":
		return executeBadIP(ctx, name, values, services)
	case "iam_anomalous_grant":
		return executeIamAnomalousGrant(ctx, name, values, services)
	case "ssh_brute_force":
		return executeSSHBruteForce(ctx, name, values, services)
	case "public_bucket_acl":
		return executePublicBucketACL(ctx, name, values, services)
	case "bucket_policy_only_disabled":
		return executeBucketPolicyOnlyDisabled(ctx, name, values, services)
	case "public_sql_instance":
		return executePublicSQLInstance(ctx, name, values, services)
	case "ssl_not_enforced":
		return executeSSLNotEnforced(ctx, name, values, services)
	case "sql_no_root_password":
		return executeSQLNoRootPassword(ctx, name, values, services)
	case "public_ip_address":
		return executePublicIPAddress(ctx, name, values, services)
	case "open_firewall":
		return executeOpenFirewall(ctx, name, values, services)
	case "open_ssh_port":
		return executeOpenSSHPort(ctx, name, values, services)
	case "open_rdp_port":
		return executeOpenRDPPort(ctx, name, values, services)
	case "public_dataset":
		return executePublicDataset(ctx, name, values, services)
	case "audit_logging_disabled":
		return executeAuditLoggingDisabled(ctx, name, values, services)
	case "web_ui_enabled":
		return executeWebUIEnabled(ctx, name, values, services)
	case "non_org_iam_member":
		return executeNonOrgIamMember(ctx, name, values, services)
	default:
		return fmt.Errorf("rule %q not found", name)
	}
}

func executeBadIP(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.ETD.BadIP
	badIP, err := badip.New(values.Finding)
	if err != nil {
		return err
	}
	if badIP.UseCSCC {
		securityMarks := badIP.BadIPCSCC.GetFinding().GetSecurityMarks().GetMarks()
		remediated := securityMarks[originalEventTime] == badIP.BadIPCSCC.GetFinding().GetEventTime()
		if remediated {
			log.Printf("finding already remediated")
			return nil
		}
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "gce_create_disk_snapshot":
			values := badIP.CreateSnapshot()
			values.DryRun = automation.Properties.DryRun
			values.Output = automation.Properties.CreateSnapshot.Output
			values.DestProjectID = automation.Properties.CreateSnapshot.TargetSnapshotProjectID
			values.DestZone = automation.Properties.CreateSnapshot.TargetSnapshotZone
			values.Turbinia.ProjectID = automation.Properties.CreateSnapshot.Turbinia.ProjectID
			values.Turbinia.Topic = automation.Properties.CreateSnapshot.Turbinia.Topic
			values.Turbinia.Zone = automation.Properties.CreateSnapshot.Turbinia.Zone
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if badIP.UseCSCC {
		if err := markAsRemediated(ctx, badIP.BadIPCSCC.GetFinding().GetName(), badIP.BadIPCSCC.GetFinding().GetEventTime(), services); err != nil {
			return err
		}
	}
	return nil
}

func executeIamAnomalousGrant(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.ETD.AnomalousIAM
	anomalousIAM, err := anomalousiam.New(values.Finding)
	if err != nil {
		return err
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "iam_revoke":
			values := anomalousIAM.IAMRevoke()
			values.DryRun = automation.Properties.DryRun
			values.AllowDomains = automation.Properties.RevokeIAM.AllowDomains
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	return nil
}

func executeSSHBruteForce(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.ETD.SSHBruteForce
	sshBruteForce, err := sshbruteforce.New(values.Finding)
	if err != nil {
		return err
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "remediate_firewall":
			values := sshBruteForce.OpenFirewall()
			values.DryRun = automation.Properties.DryRun
			values.Action = "block_ssh"
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	return nil
}

func executePublicBucketACL(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.PublicBucketACL
	storageScanner, err := storagescanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := storageScanner.StorageScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == storageScanner.StorageScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "close_bucket":
			values := storageScanner.CloseBucket()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, storageScanner.StorageScanner.GetFinding().GetName(), storageScanner.StorageScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeBucketPolicyOnlyDisabled(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.BucketPolicyOnlyDisable
	storageScanner, err := storagescanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := storageScanner.StorageScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == storageScanner.StorageScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "enable_bucket_only_policy":
			values := storageScanner.EnableBucketOnlyPolicy()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, storageScanner.StorageScanner.GetFinding().GetName(), storageScanner.StorageScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executePublicSQLInstance(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.PublicSQLInstance
	sqlScanner, err := sqlscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := sqlScanner.SQLScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == sqlScanner.SQLScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "close_cloud_sql":
			values := sqlScanner.RemovePublic()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, sqlScanner.SQLScanner.GetFinding().GetName(), sqlScanner.SQLScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeSSLNotEnforced(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.SSLNotEnforced
	sqlScanner, err := sqlscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := sqlScanner.SQLScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == sqlScanner.SQLScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "cloud_sql_require_ssl":
			values := sqlScanner.RequireSSL()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, sqlScanner.SQLScanner.GetFinding().GetName(), sqlScanner.SQLScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeSQLNoRootPassword(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.SQLNoRootPassword
	sqlScanner, err := sqlscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := sqlScanner.SQLScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == sqlScanner.SQLScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "cloud_sql_update_password":
			values, err := sqlScanner.UpdatePassword()
			if err != nil {
				services.Logger.Error("failed to get values for %q: %q", automation.Action, err)
				continue
			}
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, sqlScanner.SQLScanner.GetFinding().GetName(), sqlScanner.SQLScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executePublicIPAddress(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.PublicIPAddress
	computeInstanceScanner, err := computeinstancescanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := computeInstanceScanner.ComputeInstanceScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == computeInstanceScanner.ComputeInstanceScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "remove_public_ip":
			values := computeInstanceScanner.RemovePublicIP()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, computeInstanceScanner.ComputeInstanceScanner.GetFinding().GetName(), computeInstanceScanner.ComputeInstanceScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeOpenFirewall(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.OpenFirewall
	firewallScanner, err := firewallscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := firewallScanner.FirewallScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == firewallScanner.FirewallScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "remediate_firewall":
			values := firewallScanner.OpenFirewall()
			values.DryRun = automation.Properties.DryRun
			values.SourceRanges = automation.Properties.OpenFirewall.SourceRanges
			values.Action = automation.Properties.OpenFirewall.RemediationAction
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, firewallScanner.FirewallScanner.GetFinding().GetName(), firewallScanner.FirewallScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeOpenSSHPort(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.OpenFirewall
	firewallScanner, err := firewallscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := firewallScanner.FirewallScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == firewallScanner.FirewallScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "remediate_firewall":
			values := firewallScanner.OpenFirewall()
			values.DryRun = automation.Properties.DryRun
			values.SourceRanges = automation.Properties.OpenFirewall.SourceRanges
			values.Action = automation.Properties.OpenFirewall.RemediationAction
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, firewallScanner.FirewallScanner.GetFinding().GetName(), firewallScanner.FirewallScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeOpenRDPPort(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.OpenFirewall
	firewallScanner, err := firewallscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := firewallScanner.FirewallScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == firewallScanner.FirewallScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "remediate_firewall":
			values := firewallScanner.OpenFirewall()
			values.DryRun = automation.Properties.DryRun
			values.SourceRanges = automation.Properties.OpenFirewall.SourceRanges
			values.Action = automation.Properties.OpenFirewall.RemediationAction
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, firewallScanner.FirewallScanner.GetFinding().GetName(), firewallScanner.FirewallScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executePublicDataset(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.PublicDataset
	publicDataset, err := datasetscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := publicDataset.DatasetScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == publicDataset.DatasetScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "close_public_dataset":
			values := publicDataset.ClosePublicDataset()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, publicDataset.DatasetScanner.GetFinding().GetName(), publicDataset.DatasetScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeAuditLoggingDisabled(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.AuditLoggingDisabled
	loggingScanner, err := loggingscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := loggingScanner.Loggingscanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == loggingScanner.Loggingscanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "enable_audit_logs":
			values := loggingScanner.EnableAuditLogs()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, loggingScanner.Loggingscanner.GetFinding().GetName(), loggingScanner.Loggingscanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeWebUIEnabled(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.WebUIEnabled
	containerScanner, err := containerscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := containerScanner.Containerscanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == containerScanner.Containerscanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "disable_dashboard":
			values := containerScanner.DisableDashboard()
			values.DryRun = automation.Properties.DryRun
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, containerScanner.Containerscanner.GetFinding().GetName(), containerScanner.Containerscanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func executeNonOrgIamMember(ctx context.Context, name string, values *Values, services *Services) error {
	automations := services.Configuration.Spec.Parameters.SHA.NonOrgMembers
	iamScanner, err := iamscanner.New(values.Finding)
	if err != nil {
		return err
	}
	securityMarks := iamScanner.IAMScanner.GetFinding().GetSecurityMarks().GetMarks()
	remediated := securityMarks[originalEventTime] == iamScanner.IAMScanner.GetFinding().GetEventTime()
	if remediated {
		log.Printf("finding already remediated")
		return nil
	}
	log.Printf("got rule %q with %d automations", name, len(automations))
	for _, automation := range automations {
		switch automation.Action {
		case "remove_non_org_members":
			values := iamScanner.RemoveNonOrgMembers()
			values.DryRun = automation.Properties.DryRun
			values.AllowDomains = automation.Properties.NonOrgMembers.AllowDomains
			topic := topics[automation.Action].Topic
			if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
				services.Logger.Error("failed to publish: %q", err)
				continue
			}
		default:
			return fmt.Errorf("action %q not found", automation.Action)
		}
	}
	if err := markAsRemediated(ctx, iamScanner.IAMScanner.GetFinding().GetName(), iamScanner.IAMScanner.GetFinding().GetEventTime(), services); err != nil {
		return err
	}
	return nil
}

func publish(ctx context.Context, services *Services, action, topic, projectID string, target, exclude []string, values interface{}) error {
	ok, err := services.Resource.CheckMatches(ctx, projectID, target, exclude)
	if err != nil {
		return errors.Wrapf(err, "failed to check if project %q is within the target or is excluded", projectID)
	}
	if !ok {
		return fmt.Errorf("project %q is not within the target or is excluded", projectID)
	}
	b, err := json.Marshal(&values)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal when running %q", action)
	}
	if _, err := services.PubSub.Publish(ctx, topic, &pubsub.Message{
		Data: b,
	}); err != nil {
		services.Logger.Error("failed to publish to %q for action %q", topic, action)
		return err
	}
	log.Printf("sent to pubsub topic: %q", topic)
	return nil
}
