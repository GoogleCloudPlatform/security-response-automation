package cloudfunctions

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

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/iam"
	"cloud.google.com/go/pubsub"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

const (
	publicBucketFinding = `{
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
	otherFinding = `{
	"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
	"finding": {
	  "name": "organizations/154584661726/sources/2673592633662526977/findings/b16185f412d8a9b89d5615827f095df7",
	  "parent": "organizations/154584661726/sources/2673592633662526977",
	  "resourceName": "//compute.googleapis.com/projects/potent-minutia-246715/global/firewalls/8415669281173672995",
	  "state": "ACTIVE",
	  "category": "SOMETHING_ELSE",
	  "externalUri": "https://console.cloud.google.com/networking/firewalls/details/allow-mysql-3306?project=potent-minutia-246715",
	  "sourceProperties": {
		"ScannerName": "STORAGE_SCANNER"
	  },
	  "securityMarks": {
		"name": "organizations/154584661726/sources/2673592633662526977/findings/b16185f412d8a9b89d5615827f095df7/securityMarks",
		"marks": {
		  "f": "f"
		}
	  },
	  "eventTime": "2019-09-23T22:10:56.633Z",
	  "createTime": "2019-09-23T17:20:28.054Z"
	}
  }`
)

func TestCloseBucket(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name           string
		expectedError  string
		incomingLog    pubsub.Message
		initialMembers []string
		folderIDs      []string
		expected       []string
		ancestry       *crm.GetAncestryResponse
	}{
		{
			name:           "remove allUsers",
			incomingLog:    pubsub.Message{Data: []byte(publicBucketFinding)},
			initialMembers: []string{"allUsers", "member:tom@tom.com"},
			folderIDs:      []string{"123"},
			expected:       []string{"member:tom@tom.com"},
			ancestry:       createAncestors([]string{"folder/123"}),
		},
		{
			name:           "wrong finding category",
			incomingLog:    pubsub.Message{Data: []byte(otherFinding)},
			initialMembers: []string{"allUsers", "member:tom@tom.com"},
			folderIDs:      []string{"123"},
			expected:       nil,
			ancestry:       createAncestors([]string{"folder/123"}),
		},
		{
			name:           "no folders",
			incomingLog:    pubsub.Message{Data: []byte(otherFinding)},
			initialMembers: []string{"allUsers", "member:tom@tom.com"},
			folderIDs:      nil,
			expected:       nil,
			ancestry:       createAncestors([]string{"folder/123"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, crmStub, storageStub := closeBucketSetup(tt.folderIDs)
			crmStub.GetAncestryResponse = tt.ancestry
			for _, v := range tt.initialMembers {
				storageStub.BucketPolicyResponse.Add(v, "project/viewer")
			}

			if err := CloseBucket(ctx, tt.incomingLog, ent); err != nil {
				t.Errorf("%s test failed want:%q", tt.name, err)
			}

			if tt.expected != nil {
				s := storageStub.RemoveBucketPolicy.Members("project/viewer")
				if diff := cmp.Diff(s, tt.expected); diff != "" {
					t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expected, s)
				}
			}
		})
	}
}

func closeBucketSetup(folderIDs []string) (*entities.Entity, *stubs.ResourceManagerStub, *stubs.StorageStub) {
	loggerStub := &stubs.LoggerStub{}
	log := entities.NewLogger(loggerStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	res := entities.NewResource(crmStub, storageStub)
	storageStub.BucketPolicyResponse = &iam.Policy{}
	conf := &entities.Configuration{
		CloseBucket: &entities.CloseBucket{
			Resources: &entities.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &entities.Entity{Logger: log, Resource: res, Configuration: conf}, crmStub, storageStub
}
