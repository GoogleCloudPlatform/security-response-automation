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
	"io/ioutil"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/closebucket"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/enableauditlogs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/iam/removenonorgmembers"
	"github.com/googlecloudplatform/security-response-automation/services"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	sccv1pb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1"
	sccpb "google.golang.org/genproto/googleapis/cloud/securitycenter/v1beta1"
)

// testData reads a file from the testdata directory and returns its bytes. If an error is
// encountered while reading the file, the test will be failed.
func testData(t *testing.T, filename string) []byte {
	p := "testdata/" + filename
	b, err := ioutil.ReadFile(p)
	if err != nil {
		t.Fatalf("Could not read %s: %v", p, err)
	}

	return b
}

func TestRouter(t *testing.T) {
	const (
		validBadIP = `{
			"jsonPayload": {
				"properties": {
					"instanceDetails": "/projects/test-project/zones/zone-name/instances/source-instance-name",
					"network": {
						"project": "test-project"
					}
				},
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
		validBadIPSCC = `{
			"notificationConfigName": "organizations/0000000000000/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5",
				"parent": "organizations/0000000000000/sources/0000000000000000000",
				"resourceName": "//cloudresourcemanager.googleapis.com/projects/000000000000",
				"state": "ACTIVE",
				"category": "C2: Bad IP",
				"externalUri": "https://console.cloud.google.com/home?project=test-project-15511551515",
				"sourceProperties": {
					"detectionCategory": {
						"ruleName": "bad_ip"
					},
					"properties": {
						"instanceDetails": "/projects/test-project-15511551515/zones/us-central1-a/instances/bad-ip-caller",
							"network": {
   								"project": "test-project-15511551515"
							}
					}
				},
				"securityMarks": {
					"name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5/securityMarks",
					"marks": {
						"sra-remediated-event-time": "2019-11-22T18:34:00.000Z"
					}
				},
				"eventTime": "2019-11-22T18:34:36.153Z",
				"createTime": "2019-11-22T18:34:36.688Z"
			}
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
			"createTime": "2019-10-22T21:01:39.098Z"
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
	)
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

	sccCreateSnapshotValues := &createsnapshot.Values{
		ProjectID: "test-project-15511551515",
		RuleName:  "bad_ip",
		Instance:  "bad-ip-caller",
		Zone:      "us-central1-a",
		DryRun:    false,
	}
	sccCreateSnapshot, _ := json.Marshal(sccCreateSnapshotValues)

	conf.Spec.Parameters.SHA.PublicBucketACL = []Automation{
		{Action: "close_bucket", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	closeBucketValues := &closebucket.Values{
		ProjectID:  "test-project",
		BucketName: "this-is-public-on-purpose",
		DryRun:     false,
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
	}
	closePublicDataset, _ := json.Marshal(closePublicDatasetValues)

	conf.Spec.Parameters.SHA.AuditLoggingDisabled = []Automation{
		{Action: "enable_audit_logs", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	enableAuditLogsValues := &enableauditlogs.Values{
		ProjectID: "test-project",
		DryRun:    false,
	}
	enableAuditLog, _ := json.Marshal(enableAuditLogsValues)

	conf.Spec.Parameters.SHA.NonOrgMembers = []Automation{
		{Action: "remove_non_org_members", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	removeNonOrgMembersValues := &removenonorgmembers.Values{
		ProjectID: "test-project",
		DryRun:    false,
	}
	removeNonOrgMembers, _ := json.Marshal(removeNonOrgMembersValues)

	for _, tt := range []struct {
		name    string
		mapTo   []byte
		finding []byte
		nonSCC  bool
	}{
		{
			name:    "audit_logging_disabled",
			finding: []byte(validAuditLogDisabled),
			mapTo:   enableAuditLog,
		},
		{
			name:    "bad_ip",
			finding: []byte(validBadIP),
			nonSCC:  true,
			mapTo:   createSnapshot,
		},
		{
			name:    "bad_ip_scc",
			finding: []byte(validBadIPSCC),
			mapTo:   sccCreateSnapshot,
		},
		{
			name:    "non_org_members",
			finding: []byte(validNonOrgMembers),
			mapTo:   removeNonOrgMembers,
		},
		{
			name:    "public_bucket_acl",
			finding: []byte(validPublicBucket),
			mapTo:   closeBucket,
		},
		{
			name:    "public_dataset",
			finding: []byte(validPublicDataset),
			mapTo:   closePublicDataset,
		},
	} {
		ctx := context.Background()
		psStub := &stubs.PubSubStub{}
		ps := services.NewPubSub(psStub)
		sccStub := &stubs.SecurityCommandCenterStub{}
		scc := services.NewCommandCenter(sccStub)

		t.Run(tt.name, func(t *testing.T) {
			var nm *sccv1pb.NotificationMessage
			if !tt.nonSCC {
				nm = &sccv1pb.NotificationMessage{}
				if err := protojson.Unmarshal(tt.finding, nm); err != nil {
					t.Fatalf("Unmarshal(tt.finding) = %v, want nil \nfinding: \n%s", err, string(tt.finding))
				}
			}

			if err := Execute(ctx, &Values{
				Finding: tt.finding,
			}, &Services{
				PubSub:                ps,
				Logger:                services.NewLogger(&stubs.LoggerStub{}),
				Configuration:         conf,
				Resource:              r,
				SecurityCommandCenter: scc,
			}); err != nil {
				t.Fatalf("%q failed: %q", tt.name, err)
			}
			if diff := cmp.Diff(psStub.PublishedMessage.Data, tt.mapTo); diff != "" {
				t.Errorf("%q failed, difference:%+v", tt.name, diff)
			}

			if nm != nil {
				f := nm.GetFinding()
				want := &sccpb.UpdateSecurityMarksRequest{
					SecurityMarks: &sccpb.SecurityMarks{
						Name: f.GetName() + "/securityMarks",
						Marks: map[string]string{
							originalEventTime: f.GetEventTime().AsTime().UTC().Format(time.RFC3339Nano),
						},
					},
					UpdateMask: &fieldmaskpb.FieldMask{
						Paths: []string{"marks." + originalEventTime},
					},
				}
				if diff := cmp.Diff(want, sccStub.GetUpdateSecurityMarksRequest, protocmp.Transform()); diff != "" {
					t.Errorf("Wrong scc.AddSecurityMarks call, diff (-want +got): \n%s", diff)
				}
			}
		})
	}
}

func TestRemediated(t *testing.T) {
	for _, tt := range []struct {
		name    string
		finding string // file name under testdata/
	}{
		{name: "audit_logging_disabled", finding: "audit_logging_disabled-remediated.json"},
		{name: "bad_ip_scc", finding: "bad_ip_scc-remediated.json"},
		{name: "bucket_policy_only_disabled", finding: "bucket_policy_only_disabled-remediated.json"},
		{name: "non_org_iam_member", finding: "non_org_iam_member-remediated.json"},
		{name: "public_bucket_acl", finding: "public_bucket_acl-remediated.json"},
		{name: "public_dataset", finding: "public_dataset-remediated.json"},
	} {
		finding := testData(t, tt.finding)

		ctx := context.Background()
		psStub := &stubs.PubSubStub{}
		conf := &Configuration{}
		crmStub := &stubs.ResourceManagerStub{}
		storageStub := &stubs.StorageStub{}
		ancestryResponse := services.CreateAncestors([]string{"project/test-project", "folder/123", "organization/456"})
		crmStub.GetAncestryResponse = ancestryResponse
		r := services.NewResource(crmStub, storageStub)
		ps := services.NewPubSub(psStub)
		sccStub := &stubs.SecurityCommandCenterStub{}
		scc := services.NewCommandCenter(sccStub)

		t.Run(tt.name, func(t *testing.T) {
			if err := Execute(ctx, &Values{
				Finding: finding,
			}, &Services{
				PubSub:                ps,
				Logger:                services.NewLogger(&stubs.LoggerStub{}),
				Configuration:         conf,
				Resource:              r,
				SecurityCommandCenter: scc,
			}); err != nil {
				t.Fatalf("%q failed: %q", tt.name, err)
			}
			if psStub.PublishedMessage != nil {
				t.Errorf("%q failed, not supposed to trigger automation", tt.name)
			}
			if got := sccStub.GetUpdateSecurityMarksRequest; got != nil {
				t.Errorf("AddSecurityMarks(req) called for remediated finding \nreq: \n%+v \nfinding: \n%s", got, string(finding))
			}
		})
	}
}
