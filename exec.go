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
	"encoding/json"
	"log"
	"os"

	"cloud.google.com/go/pubsub"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/removepublic"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/requiressl"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/cloud-sql/updatepassword"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/filter"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/removepublicip"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/closebucket"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/enablebucketonlypolicy"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gke/disabledashboard"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/enableauditlogs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/removenonorgmembers"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/revoke"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/router"
	"github.com/googlecloudplatform/security-response-automation/services"
)

var (
	svcs      *services.Global
	projectID = os.Getenv("GCP_PROJECT")
)

func init() {
	log.SetFlags(log.LstdFlags | log.Llongfile)
	ctx := context.Background()
	var err error
	if projectID == "" {
		log.Fatalf("GCP_PROJECT environment variable not set")
	}
	svcs, err = services.New(ctx)
	if err != nil {
		log.Fatalf("failed to initialize services: %q", err)
	}
}

// Filter is the entry point for the Filter Cloud function.
// This function will receive all findings and filter them against
// any user-defined Rego policies before forwarding along to the
// Router function.
func Filter(ctx context.Context, m pubsub.Message) error {
	ps, err := services.InitPubSub(ctx, projectID)
	if err != nil {
		return err
	}
	return filter.Execute(ctx, m, &filter.Services{
		PubSub:                ps,
		Logger:                svcs.Logger,
		SecurityCommandCenter: svcs.SecurityCommandCenter,
	})
}

// Router is the entry point for the router Cloud Function.
//
// This Cloud Function will receive all findings and route them to configured automation.
func Router(ctx context.Context, m pubsub.Message) error {
	ps, err := services.InitPubSub(ctx, projectID)
	if err != nil {
		return err
	}
	conf, err := router.Config()
	if err != nil {
		return err
	}
	return router.Execute(ctx, &router.Values{
		Finding: m.Data,
	}, &router.Services{
		PubSub:                ps,
		Configuration:         conf,
		Logger:                svcs.Logger,
		Resource:              svcs.Resource,
		SecurityCommandCenter: svcs.SecurityCommandCenter,
	})
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
	var values revoke.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return revoke.Execute(ctx, &values, &revoke.Services{
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
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
	var values createsnapshot.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		output, err := createsnapshot.Execute(ctx, &values, &createsnapshot.Services{
			Host:   svcs.Host,
			Logger: svcs.Logger,
		})
		if err != nil {
			return err
		}
		for _, dest := range values.Output {
			switch dest {
			case "turbinia":
				log.Println("turbinia output is enabled, sending each copied disk to turbinia")
				turbiniaProjectID := values.Turbinia.ProjectID
				turbiniaTopicName := values.Turbinia.Topic
				turbiniaZone := values.Turbinia.Zone
				diskNames := output.DiskNames
				if err := services.SendTurbinia(ctx, turbiniaProjectID, turbiniaTopicName, turbiniaZone, diskNames); err != nil {
					return err
				}
				svcs.Logger.Info("sent %d disks to turbinia", len(diskNames))
			}
		}
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
	var values closebucket.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return closebucket.Execute(ctx, &values, &closebucket.Services{
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
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
	var values openfirewall.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		err := openfirewall.Execute(ctx, &values, &openfirewall.Services{
			Firewall: svcs.Firewall,
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
		if err != nil {
			return err
		}
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
	var values removenonorgmembers.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return removenonorgmembers.Execute(ctx, &values, &removenonorgmembers.Services{
			Logger:   svcs.Logger,
			Resource: svcs.Resource,
		})
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
	var values removepublicip.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return removepublicip.Execute(ctx, &values, &removepublicip.Services{
			Host:     svcs.Host,
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
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
	var values closepublicdataset.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		bigquery, err := services.InitBigQuery(ctx, values.ProjectID)
		if err != nil {
			return err
		}
		return closepublicdataset.Execute(ctx, &values, &closepublicdataset.Services{
			BigQuery: bigquery,
			Logger:   svcs.Logger,
		})
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
	var values enablebucketonlypolicy.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return enablebucketonlypolicy.Execute(ctx, &values, &enablebucketonlypolicy.Services{
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
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
	var values removepublic.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return removepublic.Execute(ctx, &values, &removepublic.Services{
			CloudSQL: svcs.CloudSQL,
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
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
	var values requiressl.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return requiressl.Execute(ctx, &values, &requiressl.Services{
			CloudSQL: svcs.CloudSQL,
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
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
	var values disabledashboard.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return disabledashboard.Execute(ctx, &values, &disabledashboard.Services{
			Container: svcs.Container,
			Resource:  svcs.Resource,
			Logger:    svcs.Logger,
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
	var values enableauditlogs.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return enableauditlogs.Execute(ctx, &values, &enableauditlogs.Services{
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
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
	var values updatepassword.Values
	switch err := json.Unmarshal(m.Data, &values); err {
	case nil:
		return updatepassword.Execute(ctx, &values, &updatepassword.Services{
			CloudSQL: svcs.CloudSQL,
			Resource: svcs.Resource,
			Logger:   svcs.Logger,
		})
	default:
		return err
	}
}
