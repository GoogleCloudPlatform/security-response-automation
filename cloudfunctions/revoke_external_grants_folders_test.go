/*
Package cloudfunctions provides the implementation of automated actions.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cloudfunctions

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/GoogleCloudPlatform/threat-automation/clients"

	"cloud.google.com/go/pubsub"
	"github.com/kylelemons/godebug/pretty"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestRevokeExternalGrantsFolders(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name          string
		expectedError error
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
		ancestry []string
	}{
		{
			name:            "invalid finding",
			expectedError:   errors.New(`failed to read finding: "failed to unmarshal"`),
			incomingLog:     pubsub.Message{},
			initialMembers:  nil,
			folderID:        []string{""},
			disallowed:      []string{""},
			expectedMembers: nil,
			ancestry:        []string{},
		},
		{
			name:            "no folder provided and doesn't remove members",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderID:        []string{""},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@gmail.com"},
			ancestry:        []string{},
		},
		{
			name:            "remove new gmail user",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com"},
			ancestry:        []string{"projects/projectID", "folders/folderID", "organizations/organizationID"},
		},
		{
			name:            "remove new user only",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        []string{"projects/projectID", "folders/folderID", "organizations/organizationID"},
		},
		{
			name:            "domain not in disallowed list",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@foo.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@foo.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@foo.com"},
			ancestry:        []string{"projects/projectID", "folders/folderID", "organiztions/organizationID"},
		},
		{
			name:            "provide multiple folders and remove gmail users",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID", "folderID1"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        []string{"projects/projectID", "folders/folderID1", "organizations/organizationID"},
		},
		{
			name:            "cannot revoke in this folder",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID", "folderID1"},
			disallowed:      []string{"gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			ancestry:        []string{"projects/projectID", "folders/anotherfolderID", "organizations/organizationID"},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			mock := &clients.MockClients{}
			mock.AddGetPolicyFake(createPolicy(tt.initialMembers))
			mock.AddGetProjectAncestryFake(tt.ancestry)
			if err := RevokeExternalGrantsFolders(ctx, tt.incomingLog, mock, tt.folderID, tt.disallowed); !reflect.DeepEqual(err, tt.expectedError) {
				if diff := pretty.Compare(err, tt.expectedError); diff != "" {
					t.Errorf("%s failed want:%q got:%q", tt.name, tt.expectedError, diff)
				}
			}

			if mock.SavedSetPolicy == nil {
				return
			}

			if diff := pretty.Compare(mock.SavedSetPolicy.Bindings, createPolicy(tt.expectedMembers)); diff != "" {
				t.Errorf("%s failed got:%q", tt.name, diff)
			}
		})
	}
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
