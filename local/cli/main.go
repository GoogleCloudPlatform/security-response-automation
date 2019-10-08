// This package will create a CSCC notification config that sends all active findings to the
// specified Pub/Sub topic.
//
// Download the service account's key and save to `./credentials/auth.json`. Set this as your
// default credentials by running:
//
// `export GOOGLE_APPLICATION_CREDENTIALS=$(pwd)/credentials.auth.json`
//
// To authorize this client you'll need to create a service account with the following roles:
//
// 	```
// 	gcloud beta organizations add-iam-policy-binding \
//	$ORGANIZATION_ID \
//	--member="serviceAccount:$ACCOUNT" \
//	--role='roles/securitycenter.notificationConfigEditor'
// 	```
//
// The account you run the above gcloud command must have Organization Admin privileges. Once a new
// notification config is created you'll receive the name of the automatically generated service
// account associated with CSCC notifications. You'll then need to grant that service account publish
// writes to create Pub/Sub messages.
//
// ```
//	gcloud beta pubsub topics add-iam-policy-binding \
//	projects/$PROJECT_ID/topics/$TOPIC_ID \
//	--member="serviceAccount:service-997507777601@gcp-sa-scc-notification.iam.gserviceaccount.com" \
//	--role="roles/pubsub.admin"
// ```
//
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
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	securitycenter "github.com/googlecloudplatform/threat-automation/clients/cscc/apiv1p1alpha1"
	securitycenterpb "github.com/googlecloudplatform/threat-automation/clients/cscc/v1p1alpha1"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

const authFile = "./credentials/auth.json"

var (
	cmd   = flag.String("command", "list", "command to run {list,create}")
	orgID = flag.String("org-id", "", "organization ID")
	topic = flag.String("topic", "", "pubsub topic name to use")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	client, err := securitycenter.NewClient(ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		log.Fatalf("failed to init client: %q", err)
		os.Exit(1)
	}
	if *orgID == "" || *topic == "" {
		log.Fatalf("org-id and topic flags required")
		os.Exit(1)
	}
	switch *cmd {
	case "list":
		if err := list(ctx, client, *orgID, *topic); err != nil {
			log.Fatalf("failed to list: %q", err)
			os.Exit(1)
		}
	case "create":
		if err := create(ctx, client, *orgID, *topic); err != nil {
			log.Fatalf("failed to create: %q", err)
			os.Exit(1)
		}
	default:
		fmt.Printf("%s command not supported", *cmd)
	}

}

func list(ctx context.Context, client *securitycenter.Client, orgID string, pubsubTopic string) error {
	defer client.Close()
	it := client.ListNotificationConfigs(ctx, &securitycenterpb.ListNotificationConfigsRequest{
		Parent: "organizations/" + orgID,
	})
	for {
		result, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		fmt.Printf("id: %s\n", result)
	}
	return nil
}

func create(ctx context.Context, client *securitycenter.Client, orgID string, pubsubTopic string) error {
	defer client.Close()
	notificationConfig, err := client.CreateNotificationConfig(ctx, &securitycenterpb.CreateNotificationConfigRequest{
		Parent:   "organizations/" + orgID,
		ConfigId: "sampleConfigId",
		NotificationConfig: &securitycenterpb.NotificationConfig{
			Description: "Notifies active findings",
			PubsubTopic: pubsubTopic,
			EventType:   securitycenterpb.NotificationConfig_FINDING,
			NotifyConfig: &securitycenterpb.NotificationConfig_StreamingConfig_{
				StreamingConfig: &securitycenterpb.NotificationConfig_StreamingConfig{
					Filter: "state = \"ACTIVE\"",
				},
			},
		},
	})
	if err != nil {
		log.Fatalf("Failed to create notification config: %v", err)
		return err
	}
	log.Printf("New NotificationConfig created: %s\n", notificationConfig)
	return nil
}
