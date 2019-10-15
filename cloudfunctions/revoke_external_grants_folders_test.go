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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"

	"cloud.google.com/go/pubsub"
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
		ancestry *crm.GetAncestryResponse
	}{
		{
			name:            "invalid finding",
			expectedError:   entities.ErrUnmarshal,
			incomingLog:     pubsub.Message{},
			initialMembers:  nil,
			folderID:        []string{""},
			disallowed:      []string{""},
			expectedMembers: nil,
			ancestry:        createAncestors([]string{}),
		},
		{
			name:            "no folder provided and doesn't remove members",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderID:        []string{""},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: nil,
			ancestry:        createAncestors([]string{}),
		},
		{
			name:            "remove new gmail user",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com"},
			ancestry:        createAncestors([]string{"project/projectID", "folder/folderID", "organization/organizationID"}),
		},
		{
			name:            "remove new user only",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        createAncestors([]string{"project/projectID", "folder/folderID", "organization/organizationID"}),
		},
		{
			name:            "domain not in disallowed list",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@foo.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@foo.com"},
			folderID:        []string{"folderID"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@foo.com"},
			ancestry:        createAncestors([]string{"project/projectID", "folder/folderID", "organization/organizationID"}),
		},
		{
			name:            "provide multiple folders and remove gmail users",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID", "folderID1"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        createAncestors([]string{"project/projectID", "folder/folderID1", "organization/organizationID"}),
		},
		{
			name:            "cannot revoke in this folder",
			expectedError:   nil,
			incomingLog:     createMessage("user:tom@gmail.com"),
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderID:        []string{"folderID", "folderID1"},
			disallowed:      []string{"gmail.com"},
			expectedMembers: nil,
			ancestry:        createAncestors([]string{"project/projectID", "folder/anotherfolderID", "organization/organizationID"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, crmStub := revokeGrantsSetup()
			crmStub.GetPolicyResponse = &crm.Policy{Bindings: createPolicy(tt.initialMembers)}
			crmStub.GetAncestryResponse = tt.ancestry

			conf := NewConfiguration(ent.Resource)
			conf.FoldersIDs = tt.folderID
			conf.Removelist = tt.disallowed

			if err := RevokeExternalGrantsFolders(ctx, tt.incomingLog, ent, conf); err != nil {
				if !xerrors.Is(errors.Cause(err), tt.expectedError) {
					t.Errorf("%q failed want:%q got:%q", tt.name, tt.expectedError, errors.Cause(err))
				}
			}
			// Nothing to save if we expected nothing.
			if crmStub.SavedSetPolicy == nil && tt.expectedMembers == nil {
				return
			}
			if diff := cmp.Diff(crmStub.SavedSetPolicy.Bindings, createPolicy(tt.expectedMembers)); diff != "" {
				t.Errorf("%s failed diff:%q", tt.name, diff)
			}
		})
	}
}

func createAncestors(members []string) *crm.GetAncestryResponse {
	ancestors := []*crm.Ancestor{}
	// 'members' here looks like a resource string but it's really just an easy way to pass the
	// type and id in a single string easily. Note to leave off the "s" from "folders" which is added
	// downstream.
	for _, m := range members {
		mm := strings.Split(m, "/")
		ancestors = append(ancestors, &crm.Ancestor{
			ResourceId: &crm.ResourceId{
				Type: mm[0],
				Id:   mm[1],
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
				"project_id": "test-foo",
				"externalMembers": [
					"` + member + `"
				]
			}
		},
		"logName": "projects/carise-etdeng-joonix/logs/threatdetection.googleapis.com%2Fdetection"
	}`)}
}

func revokeGrantsSetup() (*entities.Entity, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	l := entities.NewLogger(loggerStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	r := entities.NewResource(crmStub, storageStub)
	return &entities.Entity{Logger: l, Resource: r}, crmStub
}
