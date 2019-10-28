// Package stubs provides testable stubs for clients.
package stubs

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

	crm "google.golang.org/api/cloudresourcemanager/v1"
)

// ResourceManagerStub provides a stub for the CRM client.
type ResourceManagerStub struct {
	GetPolicyResponse       *crm.Policy
	GetAncestryResponse     *crm.GetAncestryResponse
	SavedSetPolicy          *crm.Policy
	GetOrganizationResponse *crm.Organization
}

// GetPolicyProject is a stub of Cloud Resource Manager's GetIamPolicy.
func (s *ResourceManagerStub) GetPolicyProject(ctx context.Context, projectID string) (*crm.Policy, error) {
	return s.GetPolicyResponse, nil
}

// SetPolicyProject is a stub of Cloud Resource Manager's SetIamPolicy.
func (s *ResourceManagerStub) SetPolicyProject(ctx context.Context, projectID string, p *crm.Policy) (*crm.Policy, error) {
	s.SavedSetPolicy = p
	return s.SavedSetPolicy, nil
}

// SetPolicyProjectWithMask is a stub of Cloud Resource Manager's SetIamPolicy.
func (s *ResourceManagerStub) SetPolicyProjectWithMask(ctx context.Context, projectID string, p *crm.Policy, fields ...string) (*crm.Policy, error) {
	s.SavedSetPolicy = p
	return s.SavedSetPolicy, nil
}

// GetAncestry is a stub of Cloud Resource Manager's GetAncestry.
func (s *ResourceManagerStub) GetAncestry(context.Context, string) (*crm.GetAncestryResponse, error) {
	return s.GetAncestryResponse, nil
}

// GetPolicyOrganization is a stub of Cloud Resource Manager's GetIamPolicy.
func (s *ResourceManagerStub) GetPolicyOrganization(ctx context.Context, organizationID string) (*crm.Policy, error) {
	return s.GetPolicyResponse, nil
}

// SetPolicyOrganization is a stub of Cloud Resource Manager's SetIamPolicy.
func (s *ResourceManagerStub) SetPolicyOrganization(ctx context.Context, organizationID string, p *crm.Policy) (*crm.Policy, error) {
	s.SavedSetPolicy = p
	return s.SavedSetPolicy, nil
}

// GetOrganization is a stub of Cloud Resource Manager's GetOrganization.
func (s *ResourceManagerStub) GetOrganization(ctx context.Context, organizationID string) (*crm.Organization, error) {
	return s.GetOrganizationResponse, nil
}
