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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/openfirewall"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/closebucket"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/enableauditlogs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/removenonorgmembers"
	"github.com/googlecloudplatform/security-response-automation/services"
)

const (
	validBadIP = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project",
					"instanceDetails": "/zones/zone-name/instances/source-instance-name"
				},
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	ValidSSHBruteForce = `{
			"jsonPayload": {
				"properties": {
					"project_id": "onboarding-project",
					"loginAttempts": [{
						"authResult": "FAIL",
						"sourceIp": "10.200.0.2",
						"userName": "okokok",
						"vmName": "ssh-password-auth-debian-9"
						}, {
						"authResult": "SUCCESS",
						"sourceIp": "10.200.0.3",
						"userName": "okokok",
						"vmName": "ssh-password-auth-debian-9"
						}]
			  },
			  "detectionCategory": {
				"ruleName": "ssh_brute_force"
			  }
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	validPublicBucket = `{
			"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
			"finding": {
				"name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
				"parent": "organizations/154584661726/sources/2673592633662526977",
				"resourceName": "//storage.googleapis.com/this-is-public-on-purpose",
				"state": "ACTIVE",
				"category": "PUBLIC_BUCKET_ACL",
				"externalUri": "https://console.cloud.google.com/storage/browser/this-is-public-on-purpose",
				"sourceProperties": {
					"ReactivationCount": 0.0,
					"ExceptionInstructions": "Add the security mark \"allow_public_bucket_acl\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Go to https://console.cloud.google.com/storage/browser/this-is-public-on-purpose, click on the Permissions tab, and remove \"allUsers\" and \"allAuthenticatedUsers\" from the bucket's members.",
					"ProjectId": "test-project",
					"AssetCreationTime": "2019-09-19T20:08:29.102Z",
					"ScannerName": "STORAGE_SCANNER",
					"ScanRunId": "2019-09-23T10:20:27.204-07:00",
					"Explanation": "This bucket is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
				},
				"securityMarks": {
					"name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8/securityMarks",
					"marks": {
						"babab": "3"
					}
				},
				"eventTime": "2019-09-23T17:20:27.204Z",
				"createTime": "2019-09-23T17:20:27.934Z"
			}
		}`
	validPublicDataset = `{
			"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
			"finding": {
				"name": "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7",
				"parent": "organizations/154584661726/sources/7086426792249889955",
				"resourceName": "//bigquery.googleapis.com/projects/test-project/datasets/public_dataset123",
				"state": "ACTIVE",
				"category": "PUBLIC_DATASET",
				"externalUri": "https://console.cloud.google.com/bigquery?project=test-project&folder&organizationId=154584661726&p=test-project&d=public_dataset123&page=dataset",
				"sourceProperties": {
				  "ReactivationCount": 0,
				  "ExceptionInstructions": "Add the security mark \"allow_public_dataset\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				  "SeverityLevel": "High",
				  "Recommendation": "Go to https://console.cloud.google.com/bigquery?project=test-project&folder&organizationId=154584661726&p=test-project&d=public_dataset123&page=dataset, click \"SHARE DATASET\", search members for \"allUsers\" and \"allAuthenticatedUsers\",  and remove access for those members.",
				  "ProjectId": "test-project",
				  "AssetCreationTime": "2019-10-02T18:28:42.182Z",
				  "ScannerName": "DATASET_SCANNER",
				  "ScanRunId": "2019-10-03T11:40:22.538-07:00",
				  "Explanation": "This dataset is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
				},
				"securityMarks": {
				  "name": "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7/securityMarks"
				},
				"eventTime": "2019-10-03T18:40:22.538Z",
				"createTime": "2019-10-03T18:40:23.445Z"
			}
		}`
	validAuditLogDisabled = `{
		"finding": {
			"name": "organizations/154584661726/sources/1986930501971458034/findings/1c35bd4b4f6d7145e441f2965c32f074",
			"parent": "organizations/154584661726/sources/1986930501971458034",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/108906606255",
			"state": "ACTIVE",
			"category": "AUDIT_LOGGING_DISABLED",
			"externalUri": "https://console.cloud.google.com/iam-admin/audit/allservices?project=test-project",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_audit_logging_disabled\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "Low",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/audit/allservices?project=test-project and under \"LOG TYPE\" select \"Admin read\", \"Data read\", and \"Data write\", and then click \"SAVE\". Make sure there are no exempted users configured.",
				"ProjectId": "test-project",
				"AssetCreationTime": "2019-10-22T15:13:39.305Z",
				"ScannerName": "LOGGING_SCANNER",
				"ScanRunId": "2019-10-22T14:01:08.832-07:00",
				"Explanation": "You should enable Cloud Audit Logging for all services, to track all Admin activities including read and write access to user data."
			},
			"securityMarks": {
				"name": "organizations/154584661726/sources/1986930501971458034/findings/1c35bd4b4f6d7145e441f2965c32f074/securityMarks"
			},
			"eventTime": "2019-10-22T21:01:08.832Z",
			"createTime": "2019-10-22T21:01:39.098Z",
			"assetId": "organizations/154584661726/assets/11190834741917282179",
			"assetDisplayName": "test-project"
		   }
		}`
	validNonOrgMembers = `{
		"finding": {
			"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a",
			"parent": "organizations/1050000000008/sources/1986930501000008034",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/72300000536",
			"state": "ACTIVE",
			"category": "NON_ORG_IAM_MEMBER",
			"externalUri": "https://console.cloud.google.com/iam-admin/iam?project=test-project",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_non_org_iam_member\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "High",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?project=test-project and remove entries for users which are not in your organization (e.g. gmail.com addresses).",
				"ProjectId": "test-project",
				"AssetCreationTime": "2019-02-26T15:41:40.726Z",
				"ScannerName": "IAM_SCANNER",
				"ScanRunId": "2019-10-18T08:30:22.082-07:00",
				"Explanation": "A user outside of your organization has IAM permissions on a project or organization."
			},
			"securityMarks": {
				"name": "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a/securityMarks"
			},
			"eventTime": "2019-10-18T15:30:22.082Z",
			"createTime": "2019-10-18T15:31:58.487Z"
           }
		}`
	remediatedWebUIEnabled = `{
			"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
			"finding": {
				"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274",
				"parent": "organizations/119612413569/sources/7086426792249889955",
				"resourceName": "//container.googleapis.com/projects/test-cat-findings-clseclab/zones/us-central1-a/clusters/ex-abuse-cluster-3",
				"state": "ACTIVE",
				"category": "WEB_UI_ENABLED",
				"externalUri": "https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab",
				"sourceProperties": {
					"ReactivationCount": 0,
					"ExceptionInstructions": "Add the security mark \"allow_web_ui_enabled\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Go to https://console.cloud.google.com/kubernetes/clusters/details/us-central1-a/ex-abuse-cluster-3?project=test-cat-findings-clseclab then click \"Edit\", click \"Add-ons\", and disable \"Kubernetes dashboard\". Note that a cluster cannot be modified while it is reconfiguring itself.",
					"ProjectId": "test-cat-findings-clseclab",
					"AssetCreationTime": "2018-09-26T23:57:19+00:00",
					"ScannerName": "CONTAINER_SCANNER",
					"ScanRunId": "2019-09-30T18:20:20.151-07:00",
					"Explanation": "The Kubernetes web UI is backed by a highly privileged Kubernetes Service Account, which can be abused if compromised. If you are already using the GCP console, the Kubernetes web UI extends your attack surface unnecessarily. Learn more about how to disable the Kubernetes web UI and other techniques for hardening your Kubernetes clusters at https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#disable_kubernetes_dashboard"
				},
				"securityMarks": {
					"name": "organizations/119612413569/sources/7086426792249889955/findings/18db063343328e25a3997efaa0126274/securityMarks",
					"marks": {
						"sraRemediated": "50492dc07ec3d961ee8b91fe4addec203ccf23d309eb7d2994dc15aa7f36a6b2"
                    }
				},
				"eventTime": "2019-10-01T01:20:20.151Z",
				"createTime": "2019-03-05T22:21:01.836Z"
			}
		}`
)

func TestRouter(t *testing.T) {
	conf := &Configuration{}
	// BadIP findings should map to "gce_create_disk_snapshot".
	conf.Spec.Parameters.ETD.BadIP = []Automation{
		{Action: "gce_create_disk_snapshot", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	createSnapshotValues := &createsnapshot.Values{
		ProjectID: "test-project",
		RuleName:  "bad_ip",
		Instance:  "source-instance-name",
		Zone:      "zone-name",
	}
	createSnapshot, _ := json.Marshal(createSnapshotValues)

	conf.Spec.Parameters.ETD.SSHBruteForce = []Automation{
		{Action: "remediate_firewall", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	openFirewallValues := &openfirewall.Values{
		Action:       "block_ssh",
		ProjectID:    "onboarding-project",
		FirewallID:   "",
		SourceRanges: []string{"10.200.0.2/32", "10.200.0.3/32"},
		DryRun:       false,
		Hash:         "",
		Name:         "",
	}
	openFirewall, _ := json.Marshal(openFirewallValues)

	conf.Spec.Parameters.SHA.PublicBucketACL = []Automation{
		{Action: "close_bucket", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	closeBucketValues := &closebucket.Values{
		ProjectID:  "test-project",
		BucketName: "this-is-public-on-purpose",
		DryRun:     false,
		Hash:       "f6509a6ca7277a5ae755746a7d3c087ecaf49fcc739dd1e9c79ed4e979642055",
		Name:       "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
	}
	closeBucket, _ := json.Marshal(closeBucketValues)

	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	ancestryResponse := services.CreateAncestors([]string{"project/test-project", "folder/123", "organization/456"})
	crmStub.GetAncestryResponse = ancestryResponse

	r := services.NewResource(crmStub, storageStub)

	conf.Spec.Parameters.SHA.PublicDataset = []Automation{
		{Action: "close_public_dataset", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	closePublicDatasetValues := &closepublicdataset.Values{
		ProjectID: "test-project",
		DatasetID: "public_dataset123",
		DryRun:    false,
		Hash:      "d4f5574e7967d0ca829ccdb4dc9fea6d92b63909e8207b75a69a6cf19314da2c",
		Name:      "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7",
	}
	closePublicDataset, _ := json.Marshal(closePublicDatasetValues)

	conf.Spec.Parameters.SHA.AuditLoggingDisabled = []Automation{
		{Action: "enable_audit_logs", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	enableAuditLogsValues := &enableauditlogs.Values{
		ProjectID: "test-project",
		DryRun:    false,
		Hash:      "ae689a35e9c59ab14d59341cc0f8df5dd1846496cfe975255f2e5a6ae4788433",
		Name:      "organizations/154584661726/sources/1986930501971458034/findings/1c35bd4b4f6d7145e441f2965c32f074",
	}
	enableAuditLog, _ := json.Marshal(enableAuditLogsValues)

	conf.Spec.Parameters.SHA.NonOrgMembers = []Automation{
		{Action: "remove_non_org_members", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	removeNonOrgMembersValues := &removenonorgmembers.Values{
		ProjectID: "test-project",
		DryRun:    false,
		Hash:      "9419efc34fb3c2664c9bb68f3fee02b0c9fc2a18bae214dfd209085312d83e7a",
		Name:      "organizations/1050000000008/sources/1986930501000008034/findings/047db1bc23a4b1fb00cbaa79b468945a",
	}
	removeNonOrgMembers, _ := json.Marshal(removeNonOrgMembersValues)

	for _, tt := range []struct {
		name    string
		mapTo   []byte
		finding []byte
	}{
		{name: "ssh_brute_force", finding: []byte(ValidSSHBruteForce), mapTo: openFirewall},
		{name: "bad_ip", finding: []byte(validBadIP), mapTo: createSnapshot},
		{name: "public_bucket_acl", finding: []byte(validPublicBucket), mapTo: closeBucket},
		{name: "public_dataset", finding: []byte(validPublicDataset), mapTo: closePublicDataset},
		{name: "audit_logging_disabled", finding: []byte(validAuditLogDisabled), mapTo: enableAuditLog},
		{name: "non_org_members", finding: []byte(validNonOrgMembers), mapTo: removeNonOrgMembers},
	} {
		ctx := context.Background()
		psStub := &stubs.PubSubStub{}
		ps := services.NewPubSub(psStub)

		t.Run(tt.name, func(t *testing.T) {

			if err := Execute(ctx, &Values{
				Finding: tt.finding,
			}, &Services{
				PubSub:        ps,
				Logger:        services.NewLogger(&stubs.LoggerStub{}),
				Configuration: conf,
				Resource:      r,
			}); err != nil {
				t.Fatalf("%q failed: %q", tt.name, err)
			}
			if psStub.PublishedMessage != nil {
				if diff := cmp.Diff(psStub.PublishedMessage.Data, tt.mapTo); diff != "" {
					t.Errorf("%q failed, difference:%+v", tt.name, diff)
				}
			}
		})
	}
}

func TestRouterErrors(t *testing.T) {
	conf := &Configuration{}
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	ancestryResponse := services.CreateAncestors([]string{"project/test-project", "folder/123", "organization/456"})
	crmStub.GetAncestryResponse = ancestryResponse
	r := services.NewResource(crmStub, storageStub)

	for _, tt := range []struct {
		name           string
		mapTo          []byte
		finding        []byte
		expectedErrMsg string
	}{
		{name: "remediated_finding", finding: []byte(remediatedWebUIEnabled),
			expectedErrMsg: fmt.Sprintf("remediation ignored! Finding already processed and remediated. Security Mark: \"sraRemediated:50492dc07ec3d961ee8b91fe4addec203ccf23d309eb7d2994dc15aa7f36a6b2\"")},
	} {
		ctx := context.Background()
		t.Run(tt.name, func(t *testing.T) {
			err := Execute(ctx, &Values{
				Finding: tt.finding,
			}, &Services{
				Logger:        services.NewLogger(&stubs.LoggerStub{}),
				Configuration: conf,
				Resource:      r,
			})
			if err == nil {
				t.Fatalf("%q failed: no error happened", tt.name)
			}
			if diff := cmp.Diff(err.Error(), tt.expectedErrMsg); diff != "" {
				t.Errorf("%q failed, difference:%+v", tt.name, diff)
			}
		})
	}

}
