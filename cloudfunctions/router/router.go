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

// Namer represents findings that export their name.
type Namer interface {
	Name([]byte) string
}

// Services contains the services needed for this function.
type Services struct {
	PubSub        *services.PubSub
	Configuration *Configuration
	Logger        *services.Logger
	Resource      *services.Resource
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

// Configuration maps findings to automations.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Name       string
		Parameters struct {
			ETD struct {
				BadIP         []badip.Automation         `yaml:"bad_ip"`
				AnomalousIAM  []anomalousiam.Automation  `yaml:"anomalous_iam"`
				SSHBruteForce []sshbruteforce.Automation `yaml:"ssh_brute_force"`
			}
			SHA struct {
				PublicBucketACL         []storagescanner.Automation         `yaml:"public_bucket_acl"`
				BucketPolicyOnlyDisable []storagescanner.Automation         `yaml:"bucket_policy_only_disabled"`
				PublicSQLInstance       []sqlscanner.Automation             `yaml:"public_sql_instance"`
				SSLNotEnforced          []sqlscanner.Automation             `yaml:"ssl_not_enforced"`
				SQLNoRootPassword       []sqlscanner.Automation             `yaml:"sql_no_root_password"`
				PublicIPAddress         []computeinstancescanner.Automation `yaml:"public_ip_address"`
				OpenFirewall            []firewallscanner.Automation        `yaml:"open_firewall"`
				PublicDataset           []datasetscanner.Automation         `yaml:"bigquery_public_dataset"`
				AuditLoggingDisabled    []loggingscanner.Automation         `yaml:"audit_logging_disabled"`
				WebUIEnabled            []containerscanner.Automation       `yaml:"web_ui_enabled"`
				NonOrgMembers           []iamscanner.Automation             `yaml:"non_org_members"`
			}
		}
	}
}

// Config will return the router's configuration.
func Config() (*Configuration, error) {
	var c Configuration
	b, err := ioutil.ReadFile("./cloudfunctions/router/config.yaml")
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

// Execute will route the incoming finding to the appropriate remediations.
func Execute(ctx context.Context, values *Values, services *Services) error {
	switch name := ruleName(values.Finding); name {
	case "bad_ip":
		automations := services.Configuration.Spec.Parameters.ETD.BadIP
		badIP, err := badip.New(values.Finding)
		if err != nil {
			return err
		}
		log.Printf("got rule %q with %d automations", name, len(automations))
		for _, automation := range automations {
			switch automation.Action {
			case "gce_create_disk_snapshot":
				values := badIP.CreateSnapshot()
				values.Output = automation.Properties.Output
				values.DryRun = automation.Properties.DryRun
				values.DestProjectID = automation.Properties.TargetSnapshotProjectID
				values.DestZone = automation.Properties.TargetSnapshotZone
				values.Turbinia.ProjectID = automation.Properties.Turbinia.ProjectID
				values.Turbinia.Topic = automation.Properties.Turbinia.Topic
				values.Turbinia.Zone = automation.Properties.Turbinia.Zone
				topic := topics[automation.Action].Topic
				if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
					services.Logger.Error("failed to publish: %q", err)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "iam_anomalous_grant":
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
				topic := topics[automation.Action].Topic
				if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
					services.Logger.Error("failed to publish: %q", err)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "ssh_brute_force":
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
	case "public_bucket_acl":
		automations := services.Configuration.Spec.Parameters.SHA.PublicBucketACL
		storageScanner, err := storagescanner.New(values.Finding)
		if err != nil {
			return err
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
	case "bucket_policy_only_disabled":
		automations := services.Configuration.Spec.Parameters.SHA.BucketPolicyOnlyDisable
		storageScanner, err := storagescanner.New(values.Finding)
		if err != nil {
			return err
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
	case "public_sql_instance":
		automations := services.Configuration.Spec.Parameters.SHA.PublicSQLInstance
		sqlScanner, err := sqlscanner.New(values.Finding)
		if err != nil {
			return err
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
	case "ssl_not_enforced":
		automations := services.Configuration.Spec.Parameters.SHA.SSLNotEnforced
		sqlScanner, err := sqlscanner.New(values.Finding)
		if err != nil {
			return err
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
	case "sql_no_root_password":
		automations := services.Configuration.Spec.Parameters.SHA.SQLNoRootPassword
		sqlScanner, err := sqlscanner.New(values.Finding)
		if err != nil {
			return err
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
	case "public_ip_address":
		automations := services.Configuration.Spec.Parameters.SHA.PublicIPAddress
		computeInstanceScanner, err := computeinstancescanner.New(values.Finding)
		if err != nil {
			return err
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
	case "open_firewall":
		automations := services.Configuration.Spec.Parameters.SHA.OpenFirewall
		firewallScanner, err := firewallscanner.New(values.Finding)
		if err != nil {
			return err
		}
		log.Printf("got rule %q with %d automations", name, len(automations))
		for _, automation := range automations {
			switch automation.Action {
			case "remediate_firewall":
				values := firewallScanner.OpenFirewall()
				values.DryRun = automation.Properties.DryRun
				values.SourceRanges = automation.Properties.SourceRanges
				values.Action = automation.Properties.RemediationAction
				topic := topics[automation.Action].Topic
				if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
					services.Logger.Error("failed to publish: %q", err)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "open_ssh_port":
		automations := services.Configuration.Spec.Parameters.SHA.OpenFirewall
		firewallScanner, err := firewallscanner.New(values.Finding)
		if err != nil {
			return err
		}
		log.Printf("got rule %q with %d automations", name, len(automations))
		for _, automation := range automations {
			switch automation.Action {
			case "remediate_firewall":
				values := firewallScanner.OpenFirewall()
				values.DryRun = automation.Properties.DryRun
				values.SourceRanges = automation.Properties.SourceRanges
				values.Action = automation.Properties.RemediationAction
				topic := topics[automation.Action].Topic
				if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
					services.Logger.Error("failed to publish: %q", err)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "open_rdp_port":
		automations := services.Configuration.Spec.Parameters.SHA.OpenFirewall
		firewallScanner, err := firewallscanner.New(values.Finding)
		if err != nil {
			return err
		}
		log.Printf("got rule %q with %d automations", name, len(automations))
		for _, automation := range automations {
			switch automation.Action {
			case "remediate_firewall":
				values := firewallScanner.OpenFirewall()
				values.DryRun = automation.Properties.DryRun
				values.SourceRanges = automation.Properties.SourceRanges
				values.Action = automation.Properties.RemediationAction
				topic := topics[automation.Action].Topic
				if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
					services.Logger.Error("failed to publish: %q", err)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "public_dataset":
		automations := services.Configuration.Spec.Parameters.SHA.PublicDataset
		publicDataset, err := datasetscanner.New(values.Finding)
		if err != nil {
			return err
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
	case "audit_logging_disabled":
		automations := services.Configuration.Spec.Parameters.SHA.AuditLoggingDisabled
		loggingScanner, err := loggingscanner.New(values.Finding)
		if err != nil {
			return err
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
	case "web_ui_enabled":
		automations := services.Configuration.Spec.Parameters.SHA.WebUIEnabled
		containerScanner, err := containerscanner.New(values.Finding)
		if err != nil {
			return err
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
	case "non_org_iam_member":
		automations := services.Configuration.Spec.Parameters.SHA.NonOrgMembers
		iamScanner, err := iamscanner.New(values.Finding)
		if err != nil {
			return err
		}
		log.Printf("got rule %q with %d automations", name, len(automations))
		for _, automation := range automations {
			switch automation.Action {
			case "remove_non_org_members":
				values := iamScanner.RemoveNonOrgMembers()
				values.DryRun = automation.Properties.DryRun
				values.AllowDomains = automation.Properties.AllowDomains
				topic := topics[automation.Action].Topic
				if err := publish(ctx, services, automation.Action, topic, values.ProjectID, automation.Target, automation.Exclude, values); err != nil {
					services.Logger.Error("failed to publish: %q", err)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}

	default:
		return fmt.Errorf("rule %q not found", name)
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
