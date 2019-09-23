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

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/kylelemons/godebug/pretty"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestRevokeExternalGrantsFolders(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name          string
		expectedError string
		// Incoming finding.
		incomingLog pubsub.Message
		// Initial set of members on IAM policy from `GetIamPolicy`.
		initialMembers []string
		// folderID specifies which folder to remove members from.
		folderID []string
		// disallowed is the domains disallowed in the IAM policy.
		disallowed []string
		// Set members from `SetIamPolicy`.
		expectedMembers []string
		// Incoming project's ancestry.
		ancestry *crm.GetAncestryResponse
	}{
		{
			name:            "invalid finding",
			expectedError:   `failed to read finding: "failed to unmarshal"`,
			incomingLog:     pubsub.Message{},
			initialMembers:  nil,
			folderID:        []string{""},
			disallowed:      []string{""},
			expectedMembers: nil,
			ancestry:        createAncestors([]string{}),
		},
		{
			name:            "no folder provided and doesn't remove members",
			expectedError:   "",
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderID:        []string{""},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@gmail.com"},
			ancestry:        createAncestors([]string{}),
		},
		{
			name:            "remove new gmail user",
			expectedError:   "",
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com"},
			ancestry:        createAncestors([]string{"projects/projectID", "folders/folderID", "organizations/organizationID"}),
		},
		{
			name:            "remove new user only",
			expectedError:   "",
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        createAncestors([]string{"projects/projectID", "folders/folderID", "organizations/organizationID"}),
		},
		{
			name:            "domain not in disallowed list",
			expectedError:   "",
			incomingLog:     createMessage("user:tom@foo.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@foo.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@foo.com"},
			ancestry:        createAncestors([]string{"projects/projectID", "folders/folderID", "organiztions/organizationID"}),
		},
		{
			name:            "provide multiple folders and remove gmail users",
			expectedError:   "",
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID", "folderID1"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        createAncestors([]string{"projects/projectID", "folders/folderID1", "organizations/organizationID"}),
		},
		{
			name:            "cannot revoke in this folder",
			expectedError:   "",
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID", "folderID1"},
			disallowed:      []string{"gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			ancestry:        createAncestors([]string{"projects/projectID", "folders/anotherfolderID", "organizations/organizationID"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			crmStub := &stubs.ResourceManagerStub{}
			storageStub := &stubs.StorageStub{}
			r := entities.NewResource(crmStub, storageStub)
			crmStub.GetPolicyResponse = &crm.Policy{Bindings: createPolicy(tt.initialMembers)}
			crmStub.GetAncestryResponse = tt.ancestry
			if err := RevokeExternalGrantsFolders(ctx, tt.incomingLog, r, tt.folderID, tt.disallowed); err != nil {
				if tt.expectedError != err.Error() {
					t.Errorf("%s test failed want:%q", tt.name, err)
				}
			}

			if crmStub.SavedSetPolicy == nil {
				return
			}

			if diff := pretty.Compare(crmStub.SavedSetPolicy.Bindings, createPolicy(tt.expectedMembers)); diff != "" {
				t.Errorf("%s failed got:%q", tt.name, diff)
			}
		})
	}
}

func createAncestors(members []string) *crm.GetAncestryResponse {
	ancestors := []*crm.Ancestor{}
	for _, m := range members {
		ancestors = append(ancestors, &crm.Ancestor{
			ResourceId: &crm.ResourceId{
				Type: "folder",
				Id:   m,
			},
		})
	}
	return &crm.GetAncestryResponse{Ancestor: ancestors}
}

func createPolicy(members []string) []*crm.Binding {
	return []*crm.Binding{
		{
			Role:    "roles/editor",
			Members: members,
		},
	}
}

func createMessage(member string) pubsub.Message {
	return pubsub.Message{Data: []byte(`{
		"insertId": "eppsoda4",
		"jsonPayload": {
			"detectionCategory": {
				"subRuleName": "external_member_added_to_policy",
				"ruleName": "iam_anomalous_grant"
			},
			"affectedResources":[{
				"gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/test-project-1-246321"
			}],
			"properties": {
				"externalMembers": [
					"` + member + `"
				]
			}
		},
		"logName": "projects/carise-etdeng-joonix/logs/threatdetection.googleapis.com%2Fdetection"
	}`)}
}
