// Package exec is the entry point for security automation Cloud Functions.
package exec

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
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/closebucket"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/createsnapshot"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/disabledashboard"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/openfirewall"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/removepublicip"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/revokeiam"
	"github.com/googlecloudplatform/threat-automation/entities"
)

var ent *entities.Entity

func init() {
	ctx := context.Background()
	var err error
	ent, err = entities.New(ctx)
	if err != nil {
		log.Fatalf("failed to initialize entities: %q", err)
	}
}

// RevokeIAM is the entry point for the IAM revoker Cloud Function.
//
// This Cloud Function will be triggered when Event Threat Detection
// detects an anomalous IAM grant. Once triggered this function will
// attempt to revoke the external members added to the policy if they match the provided
// list of disallowed domains. Additionally this method will only remove members if the
// project they were added to is within the specified folders. This configuration allows
// you to take a remediation action only on specific members and folders. For example,
// you may have a folder "development" where users can experiment without strict policies.
// However in your "production" folder you may want to revoke any grants that ETD finds as
// long as they match the domains you specify.
//
// Permissions required
// 	- roles/resourcemanager.folderAdmin to revoke IAM grants.
//	- roles/viewer to verify the affected project is within the enforced folder.
//
func RevokeIAM(ctx context.Context, m pubsub.Message) error {
	r, err := revokeiam.ReadFinding(m.Data)
	if err != nil {
		return err
	}
	return revokeiam.Execute(ctx, r, ent)
}

// SnapshotDisk is the entry point for the auto creation of GCE snapshots Cloud Function.
//
// This Cloud Function will respond to Event Threat Detection **bad IP** findings. Once a bad IP
// finding is received this Cloud Function will look for any existing disk snapshots for the
// affected instance. If there are recent snapshots then no action is taken. If we have not
// taken a snapshot recently, take a new snapshot for each disk within the instance.
//
// Permissions required
//	- roles/compute.instanceAdmin.v1 to manage disk snapshots.
//
func SnapshotDisk(ctx context.Context, m pubsub.Message) error {
	r, err := createsnapshot.ReadFinding(m.Data)
	if err != nil {
		return err
	}
	return createsnapshot.Execute(ctx, r, ent)
}

// CloseBucket will remove any public users from buckets found within the provided folders.
//
// Permissions required
//	- roles/viewer to retrieve ancestry.
//	- roles/storeage.admin to modify buckets.
//
func CloseBucket(ctx context.Context, m pubsub.Message) error {
	r, err := closebucket.ReadFinding(m.Data)
	if err != nil {
		return err
	}
	return closebucket.Execute(ctx, r, ent)
}

// OpenFirewall will remediate an open firewall.
//
// Permissions required
//	- roles/viewer to retrieve ancestry.
//	- roles/compute.securityAdmin to modify firewall rules.
//
func OpenFirewall(ctx context.Context, m pubsub.Message) error {
	r, err := openfirewall.ReadFinding(m.Data)
	if err != nil {
		return err
	}
	return openfirewall.Execute(ctx, r, ent)
}

// RemovePublicIP removes all the external IP addresses of a GCE instance.
//
// This Cloud Function will respond to Security Health Analytics **Public IP Address** findings
// from **Compute Instance Scanner**. All public IP addresses of the affected instance will be
// deleted when this function is activated.
//
// Permissions required
//	- roles/compute.instanceAdmin.v1 to get instance data and delete access config.
//
func RemovePublicIP(ctx context.Context, m pubsub.Message) error {
	r, err := removepublicip.ReadFinding(m.Data)
	if err != nil {
		return err
	}
	return removepublicip.Execute(ctx, r, ent)
}

// DisableDashboard will disable the Kubernetes dashboard addon.
//
// This Cloud Function will respond to Security Health Analytics **Web UI Enabled** findings
// from **Container Scanner**. The Kubernetes dashboard addon will be disabled when this
// function is activated.
//
// Permissions required
//	- roles/container.clusterAdmin update cluster addon.
//
func DisableDashboard(ctx context.Context, m pubsub.Message) error {
	r, err := disabledashboard.ReadFinding(m.Data)
	if err != nil {
		return err
	}
	return disabledashboard.Execute(ctx, r, ent)
}
