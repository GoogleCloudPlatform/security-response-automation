// Package main creates CSCC notifications.
//
// This package will create a CSCC notification config that sends all active findings to the
// specified Pub/Sub topic.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	securitycenter "github.com/googlecloudplatform/threat-automation/clients/cscc/apiv1p1alpha1"
	securitycenterpb "github.com/googlecloudplatform/threat-automation/clients/cscc/v1p1alpha1"
	"google.golang.org/api/option"
)

const authFile = "./credentials/auth.json"

func main() {
	orgID := "154584661726"
	t := "projects/aerial-jigsaw-235219/topics/cscc-notifications-topic"
	err := createNotificationConfig(orgID, t)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("success")
}

// createNotificationConfig demonstrates how to create a new notification config in Cloud SCC.
// orgID is the numeric identifier of the organization, e.g. "1231311".
// pubsubTopic is where the notifications are published to,
// e.g. "projects/myproject/topics/mytopic". You need to have
// "pubsub.topics.setIamPolicy" on the topic.
func createNotificationConfig(orgID string, pubsubTopic string) error {
	// Instantiate a context and a security service client to make API calls.
	ctx := context.Background()
	client, err := securitycenter.NewClient(ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		log.Fatalf("securitycenter.NewClient: %v", err)
		return err
	}
	defer client.Close() // Closing the client safely cleans up background resources.

	req := &securitycenterpb.CreateNotificationConfigRequest{
		Parent:   fmt.Sprintf("organizations/%s", orgID),
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
	}

	notificationConfig, err := client.CreateNotificationConfig(ctx, req)
	if err != nil {
		log.Fatalf("Failed to create notification config: %v", err)
		return err
	}
	log.Printf("New NotificationConfig created: %s\n", notificationConfig)
	return nil
}
