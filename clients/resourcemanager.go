package clients

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
	"fmt"
	"strings"

	crm "google.golang.org/api/cloudresourcemanager/v1"
)

// CloudResourceManager client.
type CloudResourceManager struct {
	service *crm.Service
}

// NewCloudResourceManager returns and initalizes the Cloud Resource Manager client.
func NewCloudResourceManager(ctx context.Context) (*CloudResourceManager, error) {
	s, err := crm.NewService(ctx)

	if err != nil {
		return nil, fmt.Errorf("failed to init crm: %q", err)
	}
	return &CloudResourceManager{service: s}, nil
}

// GetPolicyProject returns the IAM policy for the given project resource.
func (c *CloudResourceManager) GetPolicyProject(ctx context.Context, projectID string) (*crm.Policy, error) {
	return c.service.Projects.GetIamPolicy(projectID, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
}

// SetPolicyProject sets an IAM policy for the given project resource.
func (c *CloudResourceManager) SetPolicyProject(ctx context.Context, projectID string, p *crm.Policy) (*crm.Policy, error) {
	return c.service.Projects.SetIamPolicy(projectID, &crm.SetIamPolicyRequest{Policy: p}).Context(ctx).Do()
}

// SetPolicyProjectWithMask sets an IAM policy for the given project resource.
func (c *CloudResourceManager) SetPolicyProjectWithMask(ctx context.Context, projectID string, p *crm.Policy, updateField ...string) (*crm.Policy, error) {
	req := &crm.SetIamPolicyRequest{Policy: p, UpdateMask: createMask(updateField)}
	return c.service.Projects.SetIamPolicy(projectID, req).Context(ctx).Do()
}

// GetAncestry returns the ancestry for the given project.
func (c *CloudResourceManager) GetAncestry(ctx context.Context, projectID string) (*crm.GetAncestryResponse, error) {
	return c.service.Projects.GetAncestry(projectID, &crm.GetAncestryRequest{}).Context(ctx).Do()
}

// GetPolicyOrganization returns the IAM policy for the given organization resource.
func (c *CloudResourceManager) GetPolicyOrganization(ctx context.Context, name string) (*crm.Policy, error) {
	return c.service.Organizations.GetIamPolicy(name, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
}

// SetPolicyOrganization sets an IAM policy for the given organization resource.
func (c *CloudResourceManager) SetPolicyOrganization(ctx context.Context, name string, p *crm.Policy) (*crm.Policy, error) {
	return c.service.Organizations.SetIamPolicy(name, &crm.SetIamPolicyRequest{Policy: p}).Context(ctx).Do()
}

// GetOrganization returns the organization info by resource name.
func (c *CloudResourceManager) GetOrganization(ctx context.Context, name string) (*crm.Organization, error) {
	return c.service.Organizations.Get(name).Context(ctx).Do()
}

// createMask creates a string of comma separated field names to mark which fields to change.
// https://godoc.org/google.golang.org/api/cloudresourcemanager/v1beta1#SetIamPolicyRequest
func createMask(values []string) string {
	mask := append(values, "etag")
	return strings.Join(mask, ",")
}
