/*
Package automation contains the Cloud Function code to automate actions.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package automation

import (
	"fmt"

	"github.com/GoogleCloudPlatform/threat-automation/actions"
	"github.com/GoogleCloudPlatform/threat-automation/clients"

	"context"

	"cloud.google.com/go/pubsub"
)

var (
	// folderID specifies which folder RevokeExternalGrantsFolders should remove members from.
	folderIDs = []string{"670032686187"}
	// disallowed contains a list of external domains RevokeExternalGrantsFolders should remove.
	disallowed = []string{"test.com", "gmail.com"}
)

// RevokeExternalGrantsFolders is the entry point for IAM revoker Cloud Function.
//
// This sample Cloud Function will be triggered when Event Threat Detection
// detects an anomalous IAM grant. Once triggered this function will
// attempt to revoke the external members added to the policy if they contain
// domains considered disallowed. These members must also be in the folder
// specified within main.tf. This configuration allows you to take a
// remediation action only certain specific members and folders. For example,
// maybe you have a folder "development" where users can experiment and a folder
// "production". You may want to restrict and revoke external grants to the
// "production" folder and not restrict activity within "development".
//
// In order for this revoke to be possible the generated service account must have the
// appropriate permissions required. This can be accomplished in a few ways,
// grant the service account permission at the orgainization, folder or
// project level. For more information see README.md.
func RevokeExternalGrantsFolders(ctx context.Context, m pubsub.Message) error {
	c := clients.New()
	if err := c.Initialize(); err != nil {
		return fmt.Errorf("client initialize failed: %q", err)
	}

	return actions.RevokeExternalGrantsFolders(ctx, m, c, folderIDs, disallowed)
}

// SnapshotDisk sets the entry point for cloud function.
func SnapshotDisk(ctx context.Context, m pubsub.Message) error {
	c := clients.New()
	if err := c.Initialize(); err != nil {
		return fmt.Errorf("client initialize failed: %q", err)
	}
	return actions.CreateSnapshot(ctx, m, c)
}
