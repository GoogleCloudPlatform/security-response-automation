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

	"github.com/googlecloudplatform/threat-automation/clients/stubs"

	"cloud.google.com/go/storage"
	"github.com/google/go-cmp/cmp"
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

// RemoveEntityFromBucket tests the removal entities from a bucket.
func TestRemoveEntityFromBucket(t *testing.T) {
	const bucketName = "test-bucket-name"
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	r := NewResource(crmStub, storageStub)
	ctx := context.Background()
	tests := []struct {
		name                            string
		entity                          storage.ACLEntity
		expectedError                   error
		expectedSavedRemoveBucketEntity storage.ACLEntity
	}{
		{
			name:                            "delete allUsers",
			entity:                          storage.AllUsers,
			expectedError:                   nil,
			expectedSavedRemoveBucketEntity: storage.AllUsers,
		},
		{
			name:                            "delete allAuthenticatedUsers",
			entity:                          storage.AllAuthenticatedUsers,
			expectedError:                   nil,
			expectedSavedRemoveBucketEntity: storage.AllAuthenticatedUsers,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.RemoveEntityFromBucket(ctx, bucketName, tt.entity)
			if err != tt.expectedError {
				t.Errorf("%v failed exp:%v got: %v", tt.name, tt.expectedError, err)
			}
			if storageStub.RemovedBucketUsers != tt.expectedSavedRemoveBucketEntity {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedSavedRemoveBucketEntity, storageStub.RemovedBucketUsers)
			}
		})
	}
}
