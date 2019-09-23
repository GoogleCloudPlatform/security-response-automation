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
			incomingLog:    pubsub.Message{},
			initialMembers: []string{"allUsers", "member:tom@tom.com"},
			folderIDs:      []string{"123"},
			expected:       []string{"member:tom@tom.com"},
			ancestry:       createAncestors([]string{"123"}),
		},
	}
	for _, tt := range test {

		t.Run(tt.name, func(t *testing.T) {
			crmStub := &stubs.ResourceManagerStub{}
			storageStub := &stubs.StorageStub{}
			r := entities.NewResource(crmStub, storageStub)
			crmStub.GetAncestryResponse = tt.ancestry
			storageStub.BucketPolicyResponse = &iam.Policy{}

			for _, v := range tt.initialMembers {
				storageStub.BucketPolicyResponse.Add(v, "project/viewer")
			}

			if err := CloseBucket(ctx, tt.incomingLog, r, tt.folderIDs); err != nil {
				t.Errorf("%s test failed want:%q", tt.name, err)
			}

			s := storageStub.BucketPolicyResponse.Members("project/viewer")
			if diff := cmp.Diff(s, tt.expected); diff != "" {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expected, s)
			}
		})
	}
}

// func createPolicy(members []string) []*crm.Binding {
// 	return []*crm.Binding{
// 		{
// 			Role:    "roles/editor",
// 			Members: members,
// 		},
// 	}
// }

// func createMessage(member string) pubsub.Message {
// 	return pubsub.Message{Data: []byte(`{
// 		"insertId": "eppsoda4",
// 		"jsonPayload": {
// 			"detectionCategory": {
// 				"subRuleName": "external_member_added_to_policy",
// 				"ruleName": "iam_anomalous_grant"
// 			},
// 			"affectedResources":[{
// 				"gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/test-project-1-246321"
// 			}],
// 			"properties": {
// 				"externalMembers": [
// 					"` + member + `"
// 				]
// 			}
// 		},
// 		"logName": "projects/carise-etdeng-joonix/logs/threatdetection.googleapis.com%2Fdetection"
// 	}`)}
// }
