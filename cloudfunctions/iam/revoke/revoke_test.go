package revoke

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
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestIAMRevoke(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name            string
		expectedError   error
		externalMembers []string
		initialMembers  []string
		folderIDs       []string
		projectIDs      []string
		disallowed      []string
		expectedMembers []string
		ancestry        *crm.GetAncestryResponse
	}{
		{
			name:            "no folder provided and doesn't remove members",
			expectedError:   nil,
			externalMembers: []string{"user:tom@gmail.com"},
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderIDs:       []string{""},
			projectIDs:      []string{},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: nil,
			ancestry:        services.CreateAncestors([]string{}),
		},
		{
			name:            "remove new gmail user folder",
			expectedError:   nil,
			externalMembers: []string{"user:tom@gmail.com"},
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderIDs:       []string{"folderID"},
			projectIDs:      []string{},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com"},
			ancestry:        services.CreateAncestors([]string{"project/projectID", "folder/folderID", "organization/organizationID"}),
		},
		{
			name:            "remove new gmail user project",
			expectedError:   nil,
			externalMembers: []string{"user:tom@gmail.com"},
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com"},
			folderIDs:       []string{},
			projectIDs:      []string{"test-project-id"},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com"},
			ancestry:        services.CreateAncestors([]string{"project/projectID", "folder/folderID", "organization/organizationID"}),
		},
		{
			name:            "remove new user only",
			expectedError:   nil,
			externalMembers: []string{"user:tom@gmail.com"},
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderIDs:       []string{"folderID"},
			projectIDs:      []string{},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        services.CreateAncestors([]string{"project/projectID", "folder/folderID", "organization/organizationID"}),
		},
		{
			name:            "domain not in disallowed list",
			expectedError:   nil,
			externalMembers: []string{"user:tom@foo.com"},
			initialMembers:  []string{"user:test@test.com", "user:tom@foo.com"},
			folderIDs:       []string{"folderID"},
			projectIDs:      []string{},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:tom@foo.com"},
			ancestry:        services.CreateAncestors([]string{"project/projectID", "folder/folderID", "organization/organizationID"}),
		},
		{
			name:            "provide multiple folders and remove gmail users",
			expectedError:   nil,
			externalMembers: []string{"user:tom@gmail.com"},
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderIDs:       []string{"folderID", "folderID1"},
			projectIDs:      []string{},
			disallowed:      []string{"andrew.cmu.edu", "gmail.com"},
			expectedMembers: []string{"user:test@test.com", "user:existing@gmail.com"},
			ancestry:        services.CreateAncestors([]string{"project/projectID", "folder/folderID1", "organization/organizationID"}),
		},
		{
			name:            "cannot revoke in this folder",
			expectedError:   nil,
			externalMembers: []string{"user:tom@gmail.com"},
			initialMembers:  []string{"user:test@test.com", "user:tom@gmail.com", "user:existing@gmail.com"},
			folderIDs:       []string{"folderID", "folderID1"},
			projectIDs:      []string{},
			disallowed:      []string{"gmail.com"},
			expectedMembers: nil,
			ancestry:        services.CreateAncestors([]string{"project/projectID", "folder/anotherfolderID", "organization/organizationID"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, crmStub := revokeGrantsSetup(tt.folderIDs, tt.projectIDs, tt.disallowed)
			crmStub.GetPolicyResponse = &crm.Policy{Bindings: createPolicy(tt.initialMembers)}
			crmStub.GetAncestryResponse = tt.ancestry
			values := &Values{
				ProjectID:       "test-project-id",
				ExternalMembers: tt.externalMembers,
			}
			if err := Execute(ctx, values, &Services{
				Configuration: svcs.Configuration,
				Resource:      svcs.Resource,
				Logger:        svcs.Logger,
			}); err != nil {
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

func createPolicy(members []string) []*crm.Binding {
	return []*crm.Binding{
		{
			Role:    "roles/editor",
			Members: members,
		},
	}
}

func revokeGrantsSetup(folderIDs, projectIDs, disallowed []string) (*services.Global, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	l := services.NewLogger(loggerStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	r := services.NewResource(crmStub, storageStub)
	conf := &services.Configuration{
		RevokeGrants: &services.RevokeGrants{
			Resources: &services.Resources{
				FolderIDs:  folderIDs,
				ProjectIDs: projectIDs,
			},
			Removelist: disallowed,
		},
	}
	return &services.Global{Logger: l, Resource: r, Configuration: conf}, crmStub
}
