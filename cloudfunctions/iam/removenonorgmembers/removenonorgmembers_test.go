package removenonorgmembers

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
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name            string
		policyInput     []*crm.Binding
		expectedBinding []*crm.Binding
		allowDomains    []string
		expectedFail    bool
	}{
		{
			name: "empty list should fail",
			policyInput: createBindings([]string{
				"user:ddgo@cloudorg.com",
			}),
			expectedBinding: createBindings([]string{
				"user:ddgo@cloudorg.com",
			}),
			allowDomains: []string{},
			expectedFail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &crm.Policy{Bindings: tt.policyInput}
			entity, _ := setupNonOrgTest(policy)
			values := &Values{ProjectID: "project-id"}
			err := Execute(context.Background(), values, &Services{
				Resource: entity.Resource,
				Logger:   entity.Logger,
			})
			if tt.expectedFail && err == nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
		})

	}
}

func TestRemoveNonOrgMembers(t *testing.T) {
	tests := []struct {
		name            string
		policyInput     []*crm.Binding
		expectedBinding []*crm.Binding
		allowDomains    []string
	}{
		{
			name: "only remove users not in the allowed domain",
			policyInput: createBindings([]string{
				"user:anyone@google.com",
				"user:bob@gmail.com",
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"user:tim@thegmail.com",
				"group:admins@example.com",
				"domain:google.com"}),
			expectedBinding: createBindings([]string{
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"group:admins@example.com",
				"domain:google.com"}),
			allowDomains: []string{
				"cloudorg.com",
			},
		},
		{
			name: "several allowed domains",
			policyInput: createBindings([]string{
				"user:bob@gmail.com",
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"user:tim@thegmail.com",
				"user:anyone@google.com",
				"group:admins@example.com",
				"domain:aol.com",
				"user:guy@evilgoogle.com",
				"user:guy@google.evil.com",
				"user:mls@cloudorgevil.com",
				"user:mls@cloudorg.com.ev",
				"user:buddy@prod.google.com",
			}),
			expectedBinding: createBindings([]string{
				"user:ddgo@cloudorg.com",
				"user:mans@cloudorg.com",
				"serviceAccount:473000000749@cloudbuild.gserviceaccount.com",
				"user:anyone@google.com",
				"group:admins@example.com",
				"domain:aol.com",
				"user:buddy@prod.google.com",
			}),
			allowDomains: []string{
				"cloudorg.com",
				"google.com",
				"prod.google.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &crm.Policy{Bindings: tt.policyInput}
			entity, crmStub := setupNonOrgTest(policy)
			values := &Values{ProjectID: "project-id", AllowDomains: tt.allowDomains}
			err := Execute(context.Background(), values, &Services{
				Resource: entity.Resource,
				Logger:   entity.Logger,
			})
			if err != nil {
				t.Fatalf("%s failed: %q", tt.name, err)
			}
			if diff := cmp.Diff(crmStub.SavedSetPolicy.Bindings, tt.expectedBinding); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})

	}
}

func setupNonOrgTest(policy *crm.Policy) (*services.Global, *stubs.ResourceManagerStub) {
	crmStub := &stubs.ResourceManagerStub{}
	crmStub.GetPolicyResponse = policy
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	return &services.Global{
		Resource: services.NewResource(crmStub, &stubs.StorageStub{}),
		Logger:   log,
	}, crmStub
}

func createBindings(members []string) []*crm.Binding {
	return []*crm.Binding{
		{
			Role:    "roles/editor",
			Members: members,
		},
	}
}
