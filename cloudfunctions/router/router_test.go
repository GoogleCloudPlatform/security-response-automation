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
			finding: testData(t, "audit_logging_disabled.json"),
			mapTo:   enableAuditLog,
		},
		{
			name:    "bad_ip",
			finding: testData(t, "bad_ip.json"),
			nonSCC:  true,
			mapTo:   createSnapshot,
		},
		{
			name:    "bad_ip_scc",
			finding: testData(t, "bad_ip_scc.json"),
			mapTo:   sccCreateSnapshot,
		},
		{
			name:    "non_org_members",
			finding: testData(t, "non_org_iam_member.json"),
			mapTo:   removeNonOrgMembers,
		},
		{
			name:    "public_bucket_acl",
			finding: testData(t, "public_bucket_acl.json"),
			mapTo:   closeBucket,
		},
		{
			name:    "public_dataset",
			finding: testData(t, "public_dataset.json"),
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
		{name: "iam_anomalous_grant", finding: "iam_anomalous_grant-remediated.json"},
		{name: "non_org_iam_member", finding: "non_org_iam_member-remediated.json"},
		{name: "open_firewall", finding: "open_firewall-remediated.json"},
		{name: "open_rdp_port", finding: "open_rdp_port-remediated.json"},
		{name: "open_ssh_port", finding: "open_ssh_port-remediated.json"},
		{name: "public_bucket_acl", finding: "public_bucket_acl-remediated.json"},
		{name: "public_dataset", finding: "public_dataset-remediated.json"},
		{name: "public_ip_address", finding: "public_ip_address-remediated.json"},
		{name: "public_sql_instance", finding: "public_sql_instance-remediated.json"},
		{name: "sql_no_root_password", finding: "sql_no_root_password-remediated.json"},
		{name: "ssh_brute_force", finding: "ssh_brute_force-remediated.json"},
		{name: "ssl_not_enforced", finding: "ssl_not_enforced-remediated.json"},
		{name: "web_ui_enabled", finding: "web_ui_enabled-remediated.json"},
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
