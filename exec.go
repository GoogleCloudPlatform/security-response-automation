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
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/cloud-sql/removepublic"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/cloud-sql/requiressl"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/gce/openfirewall"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/gce/removepublicip"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/gcs/closebucket"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/gcs/enablebucketonlypolicy"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/gke/disabledashboard"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/iam/removenonorgmembers"
	"github.com/googlecloudplatform/threat-automation/cloudfunctions/iam/revokeiam"
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
	switch r, err := revokeiam.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return revokeiam.Execute(ctx, r, ent)
	default:
		return err
	}
}

// SnapshotDisk is the entry point for the auto creation of GCE snapshots Cloud Function.
//
// Once a bad IP finding is received this Cloud Function will look for any existing disk snapshots
// for the affected instance. If there are recent snapshots then no action is taken. If we have not
// taken a snapshot recently, take a new snapshot for each disk within the instance.
//
// Permissions required
//	- roles/compute.instanceAdmin.v1 to manage disk snapshots.
//
func SnapshotDisk(ctx context.Context, m pubsub.Message) error {
	switch v, err := createsnapshot.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return createsnapshot.Execute(ctx, v, &createsnapshot.Needed{
			Host:   ent.Host,
			Logger: ent.Logger,
		})
	default:
		return err
	}
}

// CloseBucket will remove any public users from buckets found within the provided folders.
//
// Permissions required
//	- roles/viewer to retrieve ancestry.
//	- roles/storeage.admin to modify buckets.
//
func CloseBucket(ctx context.Context, m pubsub.Message) error {
	switch r, err := closebucket.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return closebucket.Execute(ctx, r, ent)
	default:
		return err
	}
}

// OpenFirewall will remediate an open firewall.
//
// Permissions required
//	- roles/viewer to retrieve ancestry.
//	- roles/compute.securityAdmin to modify firewall rules.
//
func OpenFirewall(ctx context.Context, m pubsub.Message) error {
	switch r, err := openfirewall.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return openfirewall.Execute(ctx, r, ent)
	default:
		return err
	}
}

// RemoveNonOrganizationMember removes all members that do not match the organization domain.
//
// This Cloud Function will respond to Security Health Analytics **NON_ORG_IAM_MEMBER** findings from **IAM Scanner**.
// All user member types (user:) that do not correspond to the organization will be removed from policy binding.
//
// Permissions required
//	- roles/resourcemanager.organizationAdmin to get org info and policies and set policies.
//
func RemoveNonOrganizationMember(ctx context.Context, m pubsub.Message) error {
	switch r, err := removenonorgmembers.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return removenonorgmembers.Execute(ctx, r, ent)
	default:
		return err
	}
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
	switch r, err := removepublicip.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return removepublicip.Execute(ctx, r, ent)
	default:
		return err
	}
}

// EnableBucketOnlyPolicy Enable bucket only policy on a GCS bucket.
//
// This Cloud Function will respond to Security Health Analytics **BUCKET_POLICY_ONLY_DISABLED** findings
// from **STORAGE_SCANNER**. Bucket only IAM policy will be enforced on the bucket.
//
// Permissions required
//	- roles/storage.admin to change the Bucket policy mode.
//
func EnableBucketOnlyPolicy(ctx context.Context, m pubsub.Message) error {
	switch r, err := enablebucketonlypolicy.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return enablebucketonlypolicy.Execute(ctx, r, ent)
	default:
		return err
	}
}

// CloseCloudSQL removes public IP for a Cloud SQL instance.
//
// This Cloud Function will respond to Security Health Analytics **Public SQL Instance** findings
// from **SQL Scanner**. All public IP addresses of the affected instance will be
// deleted when this function is activated.
//
// Permissions required
//	- roles/cloudsql.editor to get instance data and delete access config.
//
func CloseCloudSQL(ctx context.Context, m pubsub.Message) error {
	switch r, err := removepublic.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return removepublic.Execute(ctx, r, ent)
	default:
		return err
	}
}

// CloudSQLRequireSSL enables the SSL requirement for a Cloud SQL instance.
//
// This Cloud Function will respond to Security Health Analytics **Public SQL Instance** findings
// from **SQL Scanner**. All public IP addresses of the affected instance will be
// deleted when this function is activated.
//
// Permissions required
//	- roles/cloudsql.editor to get instance data and delete access config.
//
func CloudSQLRequireSSL(ctx context.Context, m pubsub.Message) error {
	switch r, err := requiressl.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return requiressl.Execute(ctx, r, ent)
	default:
		return err
	}
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
	switch r, err := disabledashboard.ReadFinding(m.Data); err {
	case entities.ErrUnsupportedFinding:
		return nil
	case nil:
		return disabledashboard.Execute(ctx, r, ent)
	default:
		return err
	}
}
