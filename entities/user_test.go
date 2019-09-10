/*
Package entities contains abstractions around common objects.

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
package entities

import (
	"testing"

	"github.com/GoogleCloudPlatform/threat-automation/clients"

	stg "cloud.google.com/go/storage"
	crm "google.golang.org/api/cloudresourcemanager/v1"

	"gopkg.in/d4l3k/messagediff.v1"
)

// TestRemoveDomainsProject verifies RemoveDomains properly removes the selected domains from the given policy.
func TestRemoveDomainsProject(t *testing.T) {
	mock := &clients.MockClients{}
	r := NewUser(mock)
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
			mock.AddGetPolicyFake(tt.input)
			p, _ := r.RemoveDomainsProject(tt.name, tt.disallowedDomains)
			if diff, equal := messagediff.PrettyDiff(p.Bindings, tt.expected); !equal {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}

// TestRemoveMembersProject tests the removal of members from a policy.
func TestRemoveMembersProject(t *testing.T) {
	mock := &clients.MockClients{}
	r := NewUser(mock)
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
			mock.AddGetPolicyFake(tt.input)
			p, err := r.RemoveMembersProject(tt.name, tt.removeMembers)
			if err != nil {
				t.Errorf("%v failed, err: %+v", tt.name, err)
			}
			if diff, equal := messagediff.PrettyDiff(p.Bindings, tt.expected); !equal {
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

	mock := &clients.MockClients{}
	r := NewUser(mock)
	tests := []struct {
		name                            string
		entity                          stg.ACLEntity
		expectedError                   error
		expectedSavedRemoveBucketEntity stg.ACLEntity
	}{
		{
			name:                            "delete allUsers",
			entity:                          stg.AllUsers,
			expectedError:                   nil,
			expectedSavedRemoveBucketEntity: stg.AllUsers,
		},
		{
			name:                            "delete allAuthenticatedUsers",
			entity:                          stg.AllAuthenticatedUsers,
			expectedError:                   nil,
			expectedSavedRemoveBucketEntity: stg.AllAuthenticatedUsers,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.RemoveEntityFromBucket(bucketName, tt.entity)
			if err != tt.expectedError {
				t.Errorf("%v failed exp:%v got: %v", tt.name, tt.expectedError, err)
			}
			if mock.SavedRemoveBucketUsers != tt.expectedSavedRemoveBucketEntity {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedSavedRemoveBucketEntity, mock.SavedRemoveBucketUsers)
			}
		})
	}
}
