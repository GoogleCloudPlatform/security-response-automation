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
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gcs/closebucket"
	"github.com/googlecloudplatform/security-response-automation/providers/etd/badip"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/datasetscanner"
	"github.com/googlecloudplatform/security-response-automation/providers/sha/storagescanner"
	"github.com/googlecloudplatform/security-response-automation/services"
)

func TestRouter(t *testing.T) {
	const (
		somethingElse = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project",
					"instanceDetails": "/zones/zone-name/instances/source-instance-name"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
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
	)
	conf := &Configuration{}
	// BadIP findings should map to "gce_create_disk_snapshot".
	conf.Spec.Parameters.ETD.BadIP = []badip.Automation{
		{Action: "gce_create_disk_snapshot", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	createSnapshotValues := &createsnapshot.Values{
		ProjectID: "test-project",
		RuleName:  "bad_ip",
		Instance:  "source-instance-name",
		Zone:      "zone-name",
	}
	createSnapshot, _ := json.Marshal(createSnapshotValues)

	conf.Spec.Parameters.SHA.PublicBucketACL = []storagescanner.Automation{
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

	conf.Spec.Parameters.SHA.PublicDataset = []datasetscanner.Automation{
		{Action: "close_public_dataset", Target: []string{"organizations/456/folders/123/projects/test-project"}},
	}
	closePublicDatasetValues := &closepublicdataset.Values{
		ProjectID: "test-project",
		DatasetID: "public_dataset123",
		DryRun:    false,
	}
	closePublicDataset, _ := json.Marshal(closePublicDatasetValues)

	for _, tt := range []struct {
		name    string
		mapTo   []byte
		finding []byte
	}{
		{name: "bad_ip", finding: []byte(validBadIP), mapTo: createSnapshot},
		{name: "PUBLIC_BUCKET_ACL", finding: []byte(validPublicBucket), mapTo: closeBucket},
		{name: "PUBLIC_DATASET", finding: []byte(validPublicDataset), mapTo: closePublicDataset},
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
				t.Errorf("%q failed: %q", tt.name, err)
			}
			if diff := cmp.Diff(psStub.PublishedMessage.Data, tt.mapTo); diff != "" {
				t.Errorf("%q failed, difference:%+v", tt.name, diff)
			}
		})
	}
}
