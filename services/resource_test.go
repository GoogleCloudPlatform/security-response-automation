package services

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
	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

// TestRemoveUsersProject tests the removal of members from a policy.
func TestRemoveUsersProject(t *testing.T) {
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	r := NewResource(crmStub, storageStub)
	ctx := context.Background()
	tests := []struct {
		name          string
		input         []*crm.Binding
		removeMembers []string
		expected      []*crm.Binding
	}{
		{
			name:          "remove one member",
			input:         createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com"}),
			removeMembers: []string{"user:tim@thegmail.com"},
			expected:      createBindings([]string{"user:bob@gmail.com"}),
		},
		{
			name:          "none passed",
			input:         createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com"}),
			removeMembers: []string{},
			expected:      createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com"}),
		},
		{
			name:          "remove all",
			input:         createBindings([]string{"user:test-foo@google.com", "user:test-bob@google.com"}),
			removeMembers: []string{"user:test-foo@google.com", "user:test-bob@google.com"},
			expected:      createBindings([]string{}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crmStub.GetPolicyResponse = &crm.Policy{Bindings: tt.input}
			if err := r.RemoveUsersProject(ctx, tt.name, tt.removeMembers); err != nil {
				t.Errorf("%v failed, err: %+v", tt.name, err)
			}
			if diff := cmp.Diff(crmStub.SavedSetPolicy.Bindings, tt.expected); diff != "" {
				t.Errorf("%v failed, difference: %v", tt.name, diff)
			}

		})
	}
}

func createBindings(members []string) []*crm.Binding {
	return []*crm.Binding{
		{
			Role:    "roles/editor",
			Members: members,
		},
	}
}

// RemoveMembersFromBucket tests the removal of members from a bucket.
func TestRemoveMembersFromBucket(t *testing.T) {
	const bucketName = "test-bucket-name"
	tests := []struct {
		name            string
		toRemove        []string
		existingMembers []string
		expected        []string
	}{
		{
			name:            "delete allUsers",
			toRemove:        []string{"allUsers"},
			existingMembers: []string{"allUsers", "member:tom@tom.com"},
			expected:        []string{"member:tom@tom.com"},
		},
		{
			name:            "delete allAuthenticatedUsers",
			toRemove:        []string{"allAuthenticatedUsers"},
			existingMembers: []string{"member:tom@tom.com", "allAuthenticatedUsers", "member:foo@foo.com"},
			expected:        []string{"member:tom@tom.com", "member:foo@foo.com"},
		},
		{
			name:            "don't delete anything",
			toRemove:        []string{""},
			existingMembers: []string{"member:tom@tom.com", "allAuthenticatedUsers", "member:foo@foo.com"},
			expected:        []string{"member:tom@tom.com", "allAuthenticatedUsers", "member:foo@foo.com"},
		},
	}
	for _, tt := range tests {
		crmStub := &stubs.ResourceManagerStub{}
		storageStub := &stubs.StorageStub{}
		r := NewResource(crmStub, storageStub)
		storageStub.BucketPolicyResponse = &iam.Policy{}
		ctx := context.Background()

		for _, v := range tt.existingMembers {
			storageStub.BucketPolicyResponse.Add(v, "project/viewer")
		}

		t.Run(tt.name, func(t *testing.T) {
			err := r.RemoveMembersFromBucket(ctx, bucketName, tt.toRemove)
			if err != nil {
				t.Errorf("%v failed exp:%v got: %v", tt.name, nil, err)
			}
			s := storageStub.BucketPolicyResponse.Members("project/viewer")
			if diff := cmp.Diff(s, tt.expected); diff != "" {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expected, s)
			}
		})
	}
}

func TestRemoveNonOrganizationMembers(t *testing.T) {
	ctx := context.Background()
	const orgID = "10000111100"
	tests := []struct {
		name           string
		allowedDomains []string
		input          []*crm.Binding
		expected       []*crm.Binding
		shouldFail     bool
	}{
		{
			name:           "remove one member",
			allowedDomains: []string{"cloudorg.com"},
			input:          createBindings([]string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com", "user:tim@thegmail.com"}),
			expected:       createBindings([]string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			shouldFail:     false,
		},
		{
			name:           "remove several members",
			allowedDomains: []string{"cloudorg.com"},
			input:          createBindings([]string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com", "user:tim@thegmail.com", "user:foo@thegmail.com"}),
			expected:       createBindings([]string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			shouldFail:     false,
		},
		{
			name:           "allowed domains cannot be empty",
			allowedDomains: []string{},
			input:          createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			expected:       createBindings([]string{}),
			shouldFail:     true,
		},
		{
			name:           "none removed",
			allowedDomains: []string{"gmail.com", "thegmail.com", "cloudorg.com"},
			input:          createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			expected:       createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resource, crmStub := setupOrgTest(tt.input)
			if _, err := resource.OrganizationOnlyKeepUsersFromDomains(ctx, orgID, tt.allowedDomains); err != nil && !tt.shouldFail {
				t.Errorf("%v failed, err: %+v", tt.name, err)
			}
			if !tt.shouldFail {
				if diff := cmp.Diff(crmStub.SavedSetPolicy.Bindings, tt.expected); diff != "" {
					t.Errorf("%v failed, difference: %v", tt.name, diff)
				}
			}
		})
	}
}

func setupOrgTest(binding []*crm.Binding) (*Resource, *stubs.ResourceManagerStub) {
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	resource := NewResource(crmStub, storageStub)
	crmStub.GetPolicyResponse = &crm.Policy{Bindings: binding}
	return resource, crmStub
}

// TestEnableAuditLogsOnProject tests enable audit logs to project
func TestEnableAuditLogsOnProject(t *testing.T) {
	tests := []struct {
		name           string
		existingConfig *crm.AuditConfig
		expectedConfig []*crm.AuditConfig
	}{
		{
			name:           "enable all log types",
			existingConfig: nil,
			expectedConfig: []*crm.AuditConfig{
				{AuditLogConfigs: []*crm.AuditLogConfig{{LogType: "ADMIN_READ"}, {LogType: "DATA_READ"}, {LogType: "DATA_WRITE"}}, Service: "allServices"},
			},
		},
		{
			name: "enable all log types doesnt override existent",
			existingConfig: &crm.AuditConfig{
				AuditLogConfigs: []*crm.AuditLogConfig{{LogType: "ADMIN_READ"}}, Service: "cloudsql.googleapis.com",
			},
			expectedConfig: []*crm.AuditConfig{
				{AuditLogConfigs: []*crm.AuditLogConfig{{LogType: "ADMIN_READ"}}, Service: "cloudsql.googleapis.com"},
				{AuditLogConfigs: []*crm.AuditLogConfig{{LogType: "ADMIN_READ"}, {LogType: "DATA_READ"}, {LogType: "DATA_WRITE"}}, Service: "allServices"},
			},
		},
		{
			name: "enable all log types",
			existingConfig: &crm.AuditConfig{
				AuditLogConfigs: []*crm.AuditLogConfig{{LogType: "DATA_READ"}, {LogType: "DATA_WRITE"}}, Service: "allServices",
			},
			expectedConfig: []*crm.AuditConfig{
				{AuditLogConfigs: []*crm.AuditLogConfig{{LogType: "ADMIN_READ"}, {LogType: "DATA_READ"}, {LogType: "DATA_WRITE"}}, Service: "allServices"},
			},
		},
	}
	for _, tt := range tests {
		ctx := context.Background()
		crmStub := setupResourceManager(tt.existingConfig)

		r := NewResource(crmStub, nil)
		t.Run(tt.name, func(t *testing.T) {
			res, err := r.EnableAuditLogs(ctx, "test-project-sra")
			if err != nil {
				t.Errorf("%s failed exp:%v got:%q", tt.name, nil, err)
			}

			if diff := cmp.Diff(tt.expectedConfig, res.AuditConfigs); diff != "" {
				t.Errorf("%s failed \nexp:%v \ngot:%v", tt.name, tt.expectedConfig, res.AuditConfigs)
			}
		})
	}
}

func setupResourceManager(auditConfig *crm.AuditConfig) *stubs.ResourceManagerStub {
	var configs []*crm.AuditConfig
	if auditConfig != nil {
		configs = append(configs, auditConfig)
		return &stubs.ResourceManagerStub{GetPolicyResponse: &crm.Policy{AuditConfigs: configs}}
	}
	return &stubs.ResourceManagerStub{GetPolicyResponse: &crm.Policy{}}
}

func TestCheckMatches(t *testing.T) {
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	r := NewResource(crmStub, storageStub)
	ctx := context.Background()
	const projectID = "test-project"
	ancestryResponse := CreateAncestors([]string{"project/" + projectID, "folder/123", "organization/456"})
	tests := []struct {
		name      string
		target    string
		ignore    string
		mustMatch bool
	}{
		{name: "org in target and not in ignore", mustMatch: true, target: "organizations/456/*", ignore: "organizations/888/*"},
		{name: "org in target and in ignore", mustMatch: false, target: "organizations/456/*", ignore: "organizations/456/*"},
		{name: "org not in target and in ignore", mustMatch: false, target: "organizations/888/*", ignore: "organizations/456/*"},
		{name: "folder in target and not in ignore", mustMatch: true, target: "organizations/456/folders/123/*", ignore: "organizations/456/folders/12/*"},
		{name: "folder in target and in ignore", mustMatch: false, target: "organizations/456/folders/123/*", ignore: "organizations/456/folders/123/*"},
		{name: "folder not in target and in ignore", mustMatch: false, target: "organizations/456/folders/12/*", ignore: "organizations/456/folders/123/*"},
		{name: "project in target and not in ignore", mustMatch: true, target: "organizations/456/folders/123/projects/" + projectID, ignore: "organizations/456/folders/123/projects/other-project"},
		{name: "project in target and in ignore", mustMatch: false, target: "organizations/456/folders/123/projects/" + projectID, ignore: "organizations/456/folders/123/projects/" + projectID},
		{name: "project not in target and in ignore", mustMatch: false, target: "organizations/456/folders/123/projects/yet-other-project", ignore: "organizations/456/folders/123/projects/" + projectID},
		{name: "org not in target and not in ignore", mustMatch: false, target: "", ignore: ""},
		{name: "specify project in any folder", mustMatch: true, target: "organizations/456/*/projects/test-project", ignore: "organizations/456/folders/12/*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crmStub.GetAncestryResponse = ancestryResponse
			matches := false
			var err error
			if matches, err = r.CheckMatches(ctx, projectID, []string{tt.target}, []string{tt.ignore}); err != nil {
				t.Errorf("%s failed, err: %+v", tt.name, err)
			}
			if !tt.mustMatch && matches {
				t.Errorf("%s failed: it should not matches function but function was matches", tt.name)
			}
			if tt.mustMatch && !matches {
				t.Errorf("%s failed: it should execute function but function was not matches", tt.name)
			}
		})
	}

}
