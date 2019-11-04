package enablebucketonlypolicy

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
	"testing"

	"cloud.google.com/go/iam"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/entities/helpers"
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestReadFinding(t *testing.T) {
	const (
		storageScanner = `{
		"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
		"finding": {
		  "name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
		  "parent": "organizations/154584661726/sources/2673592633662526977",
		  "resourceName": "//storage.googleapis.com/this-is-public-on-purpose",
		  "state": "ACTIVE",
		  "category": "BUCKET_POLICY_ONLY_DISABLED",
		  "externalUri": "https://console.cloud.google.com/storage/browser/this-is-public-on-purpose",
		  "sourceProperties": {
			"ReactivationCount": 0.0,
			"ExceptionInstructions": "Add the security mark \"allow_public_bucket_acl\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
			"SeverityLevel": "High",
			"Recommendation": "Go to https://console.cloud.google.com/storage/browser/this-is-public-on-purpose, click on the Permissions tab, and remove \"allUsers\" and \"allAuthenticatedUsers\" from the bucket's members.",
			"ProjectId": "aerial-jigsaw-235219",
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
		somethingElse = `{
		"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
		"finding": {
		  "name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
		  "parent": "organizations/154584661726/sources/2673592633662526977",
		  "resourceName": "//storage.googleapis.com/this-is-public-on-purpose",
		  "state": "ACTIVE",
		  "category": "SOMETHING_ELSE",
		  "externalUri": "https://console.cloud.google.com/storage/browser/this-is-public-on-purpose",
		  "sourceProperties": {
			"ReactivationCount": 0.0,
			"ExceptionInstructions": "Add the security mark \"allow_public_bucket_acl\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
			"SeverityLevel": "High",
			"Recommendation": "Go to https://console.cloud.google.com/storage/browser/this-is-public-on-purpose, click on the Permissions tab, and remove \"allUsers\" and \"allAuthenticatedUsers\" from the bucket's members.",
			"ProjectId": "aerial-jigsaw-235219",
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
		missingProperties = `{
		"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
		"finding": {
		  "name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
		  "parent": "organizations/154584661726/sources/2673592633662526977",
		  "resourceName": "//storage.googleapis.com/this-is-public-on-purpose",
		  "state": "ACTIVE",
		  "category": "BUCKET_POLICY_ONLY_DISABLED",
		  "externalUri": "https://console.cloud.google.com/storage/browser/this-is-public-on-purpose",
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
	)
	for _, tt := range []struct {
		name, bucket, projectID string
		bytes                   []byte
		expectedError           error
	}{
		{name: "read", bucket: "this-is-public-on-purpose", projectID: "aerial-jigsaw-235219", bytes: []byte(storageScanner), expectedError: nil},
		{name: "missing properties", bucket: "", projectID: "", bytes: []byte(missingProperties), expectedError: entities.ErrValueNotFound},
		{name: "wrong category", bucket: "", projectID: "", bytes: []byte(somethingElse), expectedError: entities.ErrValueNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if r != nil && err == nil && r.BucketName != tt.bucket {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.BucketName, tt.bucket)
			}
			if r != nil && err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
			}
		})
	}
}

func TestEnableBucketOnlyPolicy(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name      string
		folderIDs []string
		expected  string
		ancestry  *crm.GetAncestryResponse
	}{
		{
			name:      "enable bucket only policy",
			folderIDs: []string{"123"},
			expected:  "bucket-to-enable-policy",
			ancestry:  helpers.CreateAncestors([]string{"folder/123"}),
		},
		{
			name:      "no folders",
			folderIDs: nil,
			expected:  "",
			ancestry:  helpers.CreateAncestors([]string{"folder/123"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, crmStub, storageStub := enableBucketOnlyPolicySetup(tt.folderIDs)
			crmStub.GetAncestryResponse = tt.ancestry

			required := &Required{
				ProjectID:  "project-name",
				BucketName: "bucket-to-enable-policy",
			}

			if err := Execute(ctx, required, ent); err != nil {
				t.Errorf("%s test failed want:%q", tt.name, err)
			}

			if tt.expected != "" {
				if s := storageStub.EnabledPolicyOnBucket; s != tt.expected {
					t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expected, s)
				}
			}
		})
	}
}

func enableBucketOnlyPolicySetup(folderIDs []string) (*entities.Entity, *stubs.ResourceManagerStub, *stubs.StorageStub) {
	loggerStub := &stubs.LoggerStub{}
	log := entities.NewLogger(loggerStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	res := entities.NewResource(crmStub, storageStub)
	storageStub.BucketPolicyResponse = &iam.Policy{}
	conf := &entities.Configuration{
		EnableBucketOnlyPolicy: &entities.EnableBucketOnlyPolicy{
			Resources: &entities.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &entities.Entity{Logger: log, Resource: res, Configuration: conf}, crmStub, storageStub
}
