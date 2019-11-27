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
	"fmt"
	"log"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/removepublic"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/requiressl"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/updatepassword"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/removepublicip"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/closebucket"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/enablebucketonlypolicy"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gke/disabledashboard"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/enableauditlogs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/removenonorgmembers"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/revoke"
	"github.com/googlecloudplatform/security-response-automation/services"
)

var svcs *services.Global

func init() {
	ctx := context.Background()
	var err error
	svcs, err = services.New(ctx)
	if err != nil {
		log.Fatalf("failed to initialize services: %q", err)
	}
	if svcs.Configuration.DryRun {
		svcs, err = services.DryRun(ctx, svcs)
		if err != nil {
			log.Fatalf("failed to initialize services: %q", err)
		}
	}
}

// IAMRevoke is the entry point for the IAM revoker Cloud Function.
//
// This function will attempt to revoke the external members added to the policy if they
// match the provided list of disallowed domains. Additionally this method will only remove
// members if the project they were added to is within the specified folders. This
// configuration allows you to take a remediation action only on specific members and folders.
// For example, you may have a folder "development" where users can experiment without strict
// policies. However in your "production" folder you may want to revoke any grants that ETD
// finds as long as they match the domains you specify.
//
// Permissions required
// 	- roles/resourcemanager.folderAdmin to revoke IAM grants.
//	- roles/viewer to verify the affected project is within the enforced folder.
//
func IAMRevoke(ctx context.Context, m pubsub.Message) error {
	switch values, err := revoke.ReadFinding(m.Data); err {
	case nil:
		return revoke.Execute(ctx, values, &revoke.Services{
			Configuration: svcs.Configuration,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	case services.ErrUnsupportedFinding:
		return nil
	default:
		return err
	}
}

// SnapshotDisk is the entry point for the auto creation of GCE snapshots Cloud Function.
//
// Once a supported finding is received this Cloud Function will look for any existing disk snapshots
// for the affected instance. If there are recent snapshots then no action is taken. This is so we
// do not overwrite a recent snapshot. If we have not taken a snapshot recently, take a new snapshot
// for each disk within the instance.
//
// Permissions required
//	- roles/compute.instanceAdmin.v1 to manage disk snapshots.
//
func SnapshotDisk(ctx context.Context, m pubsub.Message) error {
	switch values, err := createsnapshot.ReadFinding(m.Data); err {
	case nil:
		output, err := createsnapshot.Execute(ctx, values, &createsnapshot.Services{
			Configuration: svcs.Configuration,
			Host:          svcs.Host,
			Logger:        svcs.Logger,
		})
		if err != nil {
			return err
		}
		for _, dest := range svcs.Configuration.CreateSnapshot.OutputDestinations {
			switch dest {
			case "turbinia":
				log.Println("turbinia output is enabled, sending each copied disk to turbinia")
				turbiniaProjectID := svcs.Configuration.CreateSnapshot.TurbiniaProjectID
				turbiniaTopicName := svcs.Configuration.CreateSnapshot.TurbiniaTopicName
				turbiniaZone := svcs.Configuration.CreateSnapshot.TurbiniaZone
				diskNames := output.DiskNames
				if err := services.SendTurbinia(ctx, turbiniaProjectID, turbiniaTopicName, turbiniaZone, diskNames); err != nil {
					return err
				}
				svcs.Logger.Info("sent %d disks to turbinia", len(diskNames))
			}
		}
		return nil
	case services.ErrUnsupportedFinding:
		return nil
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
	switch values, err := closebucket.ReadFinding(m.Data); err {
	case nil:
		return closebucket.Execute(ctx, values, &closebucket.Services{
			Configuration: svcs.Configuration,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	case services.ErrUnsupportedFinding:
		return nil
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
	switch values, err := openfirewall.ReadFinding(m.Data); err {
	case nil:
		err := openfirewall.Execute(ctx, values, &openfirewall.Services{
			Configuration: svcs.Configuration,
			Firewall:      svcs.Firewall,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
		if err != nil {
			return err
		}
		for _, dest := range svcs.Configuration.DisableFirewall.OutputDestinations {
			switch dest {
			case "pagerduty":
				log.Println("will attempt to output to PagerDuty")
				conf := svcs.Configuration.PagerDuty
				if !conf.Enabled {
					log.Println("pagerDuty not enabled")
					continue
				}
				pd := services.InitPagerDuty(conf.APIKey)
				title := "Open firewall detected"
				body := fmt.Sprintf("automatically took action: %q", svcs.Configuration.DisableFirewall.RemediationAction)
				if err := pd.CreateIncident(ctx, conf.From, conf.ServiceID, title, body); err != nil {
					return err
				}
			}
		}
		return nil
	case services.ErrUnsupportedFinding:
		return nil
	default:
		return err
	}
}

// RemoveNonOrganizationMembers removes all members that do not match the organization domain.
//
// This Cloud Function will respond to Security Health Analytics **NON_ORG_IAM_MEMBER** findings from **IAM Scanner**.
// All user member types (user:) that do not correspond to the organization will be removed from policy binding.
//
// Permissions required
//	- roles/resourcemanager.organizationAdmin to get org info and policies and set policies.
//
func RemoveNonOrganizationMembers(ctx context.Context, m pubsub.Message) error {
	switch values, err := removenonorgmembers.ReadFinding(m.Data); err {
	case nil:
		return removenonorgmembers.Execute(ctx, values, &removenonorgmembers.Services{
			Logger:        svcs.Logger,
			Configuration: svcs.Configuration,
			Resource:      svcs.Resource,
		})
	case services.ErrUnsupportedFinding:
		return nil
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
	switch values, err := removepublicip.ReadFinding(m.Data); err {
	case nil:
		return removepublicip.Execute(ctx, values, &removepublicip.Services{
			Configuration: svcs.Configuration,
			Host:          svcs.Host,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	case services.ErrUnsupportedFinding:
		return nil
	default:
		return err
	}
}

// ClosePublicDataset removes public access of a BigQuery dataset.
//
// This Cloud Function will respond to Security Health Analytics **Public Dataset** findings
// from **Dataset Scanner**. All public access of the affected dataset will be
// removed when this function is activated.
//
// Permissions required
//	- roles/bigquery.dataOwner to get and update dataset metadata.
//
func ClosePublicDataset(ctx context.Context, m pubsub.Message) error {
	switch values, err := closepublicdataset.ReadFinding(m.Data); err {
	case nil:
		bigquery, err := services.InitBigQuery(ctx, values.ProjectID)
		if err != nil {
			return err
		}
		return closepublicdataset.Execute(ctx, values, &closepublicdataset.Services{
			Configuration: svcs.Configuration,
			BigQuery:      bigquery,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	case services.ErrUnsupportedFinding:
		return nil
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
	switch values, err := enablebucketonlypolicy.ReadFinding(m.Data); err {
	case nil:
		return enablebucketonlypolicy.Execute(ctx, values, &enablebucketonlypolicy.Services{
			Configuration: svcs.Configuration,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	case services.ErrUnsupportedFinding:
		return nil
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
	switch values, err := removepublic.ReadFinding(m.Data); err {
	case nil:
		return removepublic.Execute(ctx, values, &removepublic.Services{
			Configuration: svcs.Configuration,
			CloudSQL:      svcs.CloudSQL,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	case services.ErrUnsupportedFinding:
		return nil
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
	switch values, err := requiressl.ReadFinding(m.Data); err {
	case nil:
		return requiressl.Execute(ctx, values, &requiressl.Services{
			Configuration: svcs.Configuration,
			CloudSQL:      svcs.CloudSQL,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	case services.ErrUnsupportedFinding:
		return nil
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
	switch values, err := disabledashboard.ReadFinding(m.Data); err {
	case services.ErrUnsupportedFinding:
		return nil
	case nil:
		return disabledashboard.Execute(ctx, values, &disabledashboard.Services{
			Configuration: svcs.Configuration,
			Container:     svcs.Container,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	default:
		return err
	}
}

// EnableAuditLogs enables the Audit Logs to specific project
//
// This Cloud Function will respond to Security Health Analytics **AUDIT_LOGGING_DISABLED** findings
// from **LOGGING_SCANNER**.
//
// Permissions required
//	- roles/resourcemanager.folderAdmin to get/update resource policy from projects in folder.
//	- roles/editor to get/update resource policy to specific project.
//
func EnableAuditLogs(ctx context.Context, m pubsub.Message) error {
	switch values, err := enableauditlogs.ReadFinding(m.Data); err {
	case services.ErrUnsupportedFinding:
		return nil
	case nil:
		return enableauditlogs.Execute(ctx, values, &enableauditlogs.Services{
			Configuration: svcs.Configuration,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	default:
		return err
	}
}

// UpdatePassword updates the root password for a Cloud SQL instance.
//
// This Cloud Function will respond to Security Health Analytics **SQL No Root Password** findings
// from **SQL Scanner**. The root user of the affected instance will be updated with
// a new password when this function is activated.
//
// Permissions required
//	- roles/cloudsql.admin to update a user password.
//
func UpdatePassword(ctx context.Context, m pubsub.Message) error {
	switch values, err := updatepassword.ReadFinding(m.Data); err {
	case nil:
		return updatepassword.Execute(ctx, values, &updatepassword.Services{
			Configuration: svcs.Configuration,
			CloudSQL:      svcs.CloudSQL,
			Resource:      svcs.Resource,
			Logger:        svcs.Logger,
		})
	default:
		return err
	}
}
