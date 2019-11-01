package entities

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
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities/helpers"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

// TestRemoveDomainsProject verifies RemoveDomains properly removes the selected domains from the given policy.
func TestRemoveDomainsProject(t *testing.T) {
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	r := NewResource(crmStub, storageStub)
	ctx := context.Background()
	tests := []struct {
		name              string
		input             []*crm.Binding
		disallowedDomains []string
		expected          []*crm.Binding
	}{
		{
			name: "remove multiple members",
			input: createBindings([]string{
				"bob@gmail.com",
				"jim@other.com",
				"test-bob@google.com",
				"test-foo@gmail.com",
				"tim@thegmail.com",
				"tom@gmail.com",
			}),
			disallowedDomains: []string{
				"andrew.cmu.edu",
				"gmail.com",
			},
			expected: createBindings([]string{
				"jim@other.com",
				"test-bob@google.com",
				"tim@thegmail.com",
			}),
		},
		{
			name:              "remove single domain member",
			input:             createBindings([]string{"test-foo@gmail.com", "test-bob@google.com"}),
			disallowedDomains: []string{"gmail.com"},
			expected:          createBindings([]string{"test-bob@google.com"}),
		},
		{
			name:              "no members to remove",
			input:             createBindings([]string{"test-foo@google.com", "test-bob@google.com"}),
			disallowedDomains: []string{"gmail.com"},
			expected:          createBindings([]string{"test-foo@google.com", "test-bob@google.com"}),
		},
		{
			name:              "remove all",
			input:             createBindings([]string{"test-foo@gmail.com", "test-bob@gmail.com"}),
			disallowedDomains: []string{"gmail.com"},
			expected:          createBindings([]string{}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crmStub.GetPolicyResponse = &crm.Policy{Bindings: tt.input}
			p, _ := r.RemoveDomainsProject(ctx, tt.name, tt.disallowedDomains)
			if diff := cmp.Diff(p.Bindings, tt.expected); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}

// TestRemoveMembersProject tests the removal of members from a policy.
func TestRemoveMembersProject(t *testing.T) {
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
			p, err := r.RemoveMembersProject(ctx, tt.name, tt.removeMembers)
			if err != nil {
				t.Errorf("%v failed, err: %+v", tt.name, err)
			}
			if diff := cmp.Diff(p.Bindings, tt.expected); diff != "" {
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

// TestRemoveNonOrganizationMembers tests the removal of members from a policy at organization level.
func TestRemoveNonOrganizationMembers(t *testing.T) {
	ctx := context.Background()
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	r := NewResource(crmStub, storageStub)

	tests := []struct {
		name           string
		organizationID string
		removeMembers  []string
		input          []*crm.Binding
		expected       []*crm.Binding
	}{
		{
			name:           "remove one member",
			organizationID: "organizations/10000111100",
			removeMembers:  []string{"user:tim@thegmail.com"},
			input:          createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			expected:       createBindings([]string{"user:bob@gmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
		},
		{
			name:           "remove more than one member",
			organizationID: "organizations/10000111100",
			removeMembers:  []string{"user:bob@gmail.com", "user:tim@thegmail.com"},
			input:          createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			expected:       createBindings([]string{"user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
		},
		{
			name:           "remove all",
			organizationID: "organizations/10000111100",
			removeMembers:  []string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"},
			input:          createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			expected:       createBindings([]string{}),
		},
		{
			name:           "none passed",
			organizationID: "organizations/10000111100",
			removeMembers:  []string{},
			input:          createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
			expected:       createBindings([]string{"user:bob@gmail.com", "user:tim@thegmail.com", "user:ddgo@cloudorg.com", "user:mans@cloudorg.com"}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &crm.Policy{Bindings: tt.input}
			newPolicy, err := r.RemoveMembersOrganization(ctx, tt.organizationID, tt.removeMembers, p)
			if err != nil {
				t.Errorf("%v failed, err: %+v", tt.name, err)
			}
			if diff := cmp.Diff(newPolicy.Bindings, tt.expected); diff != "" {
				t.Errorf("%v failed, difference: %v", tt.name, diff)
			}
		})
	}
}

func TestProjectInOrg(t *testing.T) {
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	r := NewResource(crmStub, storageStub)
	ctx := context.Background()
	const projectID = "test-project"
	tests := []struct {
		name     string
		orgID    string
		ancestry *crm.GetAncestryResponse
		inOrg    bool
	}{
		{name: "in org", inOrg: true, orgID: "456", ancestry: helpers.CreateAncestors([]string{"folder/123", "organization/456"})},
		{name: "out org", inOrg: false, orgID: "888", ancestry: helpers.CreateAncestors([]string{"folder/123", "organization/456"})},
		{name: "no org", inOrg: false, orgID: "", ancestry: helpers.CreateAncestors([]string{"folder/123", "organization/456"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crmStub.GetAncestryResponse = tt.ancestry
			exec := false
			if err := r.IfProjectInOrg(ctx, tt.orgID, projectID, func() error {
				exec = true
				return nil
			}); err != nil {
				t.Errorf("%s failed, err: %+v", tt.name, err)
			}
			if !tt.inOrg && exec {
				t.Errorf("%s failed: out of org but executed function", tt.name)
			}
			if tt.inOrg && !exec {
				t.Errorf("%s failed: in org but did not execute function", tt.name)
			}
		})
	}
}
