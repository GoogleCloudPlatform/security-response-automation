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
	"github.com/googlecloudplatform/security-response-automation/providers/sha/sqlscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/storagescanner"
	"github.com/googlecloudplatform/security-response-automation/services"
	"gopkg.in/yaml.v2"
)

var findings = []Namer{
	&anomalousiam.Finding{},
	&badip.Finding{},
	&storagescanner.Finding{},
	&sqlscanner.Finding{},
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
}

// Configuration maps findings to automations.
type Configuration struct {
	APIVersion string
	Spec       struct {
		Name       string
		Parameters struct {
			ETD struct {
				BadIP        []badip.Automation        `yaml:"bad_ip"`
				AnomalousIAM []anomalousiam.Automation `yaml:"anomalous_iam"`
			}
			SHA struct {
				PublicBucketACL         []storagescanner.Automation `yaml:"public_bucket_acl"`
				BucketPolicyOnlyDisable []storagescanner.Automation `yaml:"bucket_policy_only_disabled"`
				PublicSQLInstance       []sqlscanner.Automation     `yaml:"public_sql_instance"`
				SSLNotEnforced          []sqlscanner.Automation     `yaml:"ssl_not_enforced"`
				SQLNoRootPassword       []sqlscanner.Automation     `yaml:"sql_no_root_password"`
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
		return nil, err
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
				values.Turbinia.ProjectID = automation.Properties.Turbinia.ProjectID
				values.Turbinia.Topic = automation.Properties.Turbinia.Topic
				values.Turbinia.Zone = automation.Properties.Turbinia.Zone
				ok, err := services.Resource.CheckMatches(ctx, values.ProjectID, automation.Target, automation.Exclude)
				if !ok {
					log.Printf("project %q is not within the target or is excluded", values.ProjectID)
					continue
				}
				if err != nil {
					log.Printf("failed: %q", err)
					services.Logger.Error("failed to run %q: %q", automation.Action, err)
					continue
				}
				b, err := json.Marshal(&values)
				if err != nil {
					services.Logger.Error("failed to unmarshal when runing %q: %q", automation.Action, err)
					continue
				}
				log.Printf("sending to pubsub topic: %q", topics[automation.Action].Topic)
				if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					services.Logger.Error("failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
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
		for _, automation := range automations {
			switch automation.Action {
			case "iam_revoke":
				values := anomalousIAM.IAMRevoke()
				values.DryRun = automation.Properties.DryRun
				ok, err := services.Resource.CheckMatches(ctx, values.ProjectID, automation.Target, automation.Exclude)
				if !ok {
					log.Printf("project %q is not within the target or is excluded", values.ProjectID)
					continue
				}
				if err != nil {
					services.Logger.Error("failed to run %q: %q", automation.Action, err)
					continue
				}
				b, err := json.Marshal(&values)
				if err != nil {
					services.Logger.Error("failed to unmarshal when runing %q: %q", automation.Action, err)
					continue
				}
				log.Printf("sending to pubsub topic: %q", topics[automation.Action].Topic)
				if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					services.Logger.Error("failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "PUBLIC_BUCKET_ACL":
		automations := services.Configuration.Spec.Parameters.SHA.PublicBucketACL
		storageScanner, err := storagescanner.New(values.Finding)
		if err != nil {
			return err
		}
		for _, automation := range automations {
			switch automation.Action {
			case "close_bucket":
				values := storageScanner.CloseBucket()
				values.DryRun = automation.Properties.DryRun
				ok, err := services.Resource.CheckMatches(ctx, values.ProjectID, automation.Target, automation.Exclude)
				if !ok {
					log.Printf("project %q is not within the target or is excluded", values.ProjectID)
					continue
				}
				if err != nil {
					services.Logger.Error("failed to run %q: %q", automation.Action, err)
					continue
				}
				b, err := json.Marshal(&values)
				if err != nil {
					services.Logger.Error("failed to unmarshal when runing %q: %q", automation.Action, err)
					continue
				}
				log.Printf("sending to pubsub topic: %q", topics[automation.Action].Topic)
				if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					services.Logger.Error("failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "BUCKET_POLICY_ONLY_DISABLED":
		automations := services.Configuration.Spec.Parameters.SHA.BucketPolicyOnlyDisable
		storageScanner, err := storagescanner.New(values.Finding)
		if err != nil {
			return err
		}
		for _, automation := range automations {
			switch automation.Action {
			case "enable_bucket_only_policy":
				values := storageScanner.EnableBucketOnlyPolicy()
				values.DryRun = automation.Properties.DryRun
				ok, err := services.Resource.CheckMatches(ctx, values.ProjectID, automation.Target, automation.Exclude)
				if !ok {
					log.Printf("project %q is not within the target or is excluded", values.ProjectID)
					continue
				}
				if err != nil {
					services.Logger.Error("failed to run %q: %q", automation.Action, err)
					continue
				}
				b, err := json.Marshal(&values)
				if err != nil {
					services.Logger.Error("failed to unmarshal when runing %q: %q", automation.Action, err)
					continue
				}
				log.Printf("sending to pubsub topic: %q", topics[automation.Action].Topic)
				if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					services.Logger.Error("failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "PUBLIC_SQL_INSTANCE":
		automations := services.Configuration.Spec.Parameters.SHA.PublicSQLInstance
		sqlScanner, err := sqlscanner.New(values.Finding)
		if err != nil {
			return err
		}
		for _, automation := range automations {
			switch automation.Action {
			case "close_cloud_sql":
				values := sqlScanner.RemovePublic()
				values.DryRun = automation.Properties.DryRun
				ok, err := services.Resource.CheckMatches(ctx, values.ProjectID, automation.Target, automation.Exclude)
				if !ok {
					log.Printf("project %q is not within the target or is excluded", values.ProjectID)
					continue
				}
				if err != nil {
					services.Logger.Error("failed to run %q: %q", automation.Action, err)
					continue
				}
				b, err := json.Marshal(&values)
				if err != nil {
					services.Logger.Error("failed to unmarshal when runing %q: %q", automation.Action, err)
					continue
				}
				log.Printf("sending to pubsub topic: %q", topics[automation.Action].Topic)
				if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					services.Logger.Error("failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "SSL_NOT_ENFORCED":
		automations := services.Configuration.Spec.Parameters.SHA.SSLNotEnforced
		sqlScanner, err := sqlscanner.New(values.Finding)
		if err != nil {
			return err
		}
		for _, automation := range automations {
			switch automation.Action {
			case "cloud_sql_require_ssl":
				values := sqlScanner.RequireSSL()
				values.DryRun = automation.Properties.DryRun
				ok, err := services.Resource.CheckMatches(ctx, values.ProjectID, automation.Target, automation.Exclude)
				if !ok {
					log.Printf("project %q is not within the target or is excluded", values.ProjectID)
					continue
				}
				if err != nil {
					services.Logger.Error("failed to run %q: %q", automation.Action, err)
					continue
				}
				b, err := json.Marshal(&values)
				if err != nil {
					services.Logger.Error("failed to unmarshal when runing %q: %q", automation.Action, err)
					continue
				}
				log.Printf("sending to pubsub topic: %q", topics[automation.Action].Topic)
				if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					services.Logger.Error("failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
					continue
				}
			default:
				return fmt.Errorf("action %q not found", automation.Action)
			}
		}
	case "SQL_NO_ROOT_PASSWORD":
		automations := services.Configuration.Spec.Parameters.SHA.SQLNoRootPassword
		sqlScanner, err := sqlscanner.New(values.Finding)
		if err != nil {
			return err
		}
		for _, automation := range automations {
			switch automation.Action {
			case "cloud_sql_update_password":
				values := sqlScanner.UpdatePassword()
				values.DryRun = automation.Properties.DryRun
				ok, err := services.Resource.CheckMatches(ctx, values.ProjectID, automation.Target, automation.Exclude)
				if !ok {
					log.Printf("project %q is not within the target or is excluded", values.ProjectID)
					continue
				}
				if err != nil {
					services.Logger.Error("failed to run %q: %q", automation.Action, err)
					continue
				}
				b, err := json.Marshal(&values)
				if err != nil {
					services.Logger.Error("failed to unmarshal when runing %q: %q", automation.Action, err)
					continue
				}
				log.Printf("sending to pubsub topic: %q", topics[automation.Action].Topic)
				if _, err := services.PubSub.Publish(ctx, topics[automation.Action].Topic, &pubsub.Message{
					Data: b,
				}); err != nil {
					services.Logger.Error("failed to publish to %q for action %q", topics[automation.Action].Topic, automation.Action)
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
