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
	"log"

	"github.com/googlecloudplatform/security-response-automation/services/mode"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// CloudResourceManager client.
type CloudResourceManager struct {
	service *crm.Service
}

// NewCloudResourceManager returns and initalizes the Cloud Resource Manager client.
func NewCloudResourceManager(ctx context.Context, authFile string) (*CloudResourceManager, error) {
	s, err := crm.NewService(ctx, option.WithCredentialsFile(authFile))

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
	if mode.DryRun() {
		log.Println("[DRY_RUN] set policy ", p, " on project ", projectID)
		return nil, nil
	}
	return c.service.Projects.SetIamPolicy(projectID, &crm.SetIamPolicyRequest{Policy: p}).Context(ctx).Do()
}

// GetAncestry returns the ancestry for the given project.
func (c *CloudResourceManager) GetAncestry(ctx context.Context, projectID string) (*crm.GetAncestryResponse, error) {
	return c.service.Projects.GetAncestry(projectID, &crm.GetAncestryRequest{}).Context(ctx).Do()
}

// GetPolicyOrganization returns the IAM policy for the given organization resource.
func (c *CloudResourceManager) GetPolicyOrganization(ctx context.Context, organizationID string) (*crm.Policy, error) {
	return c.service.Organizations.GetIamPolicy(organizationID, &crm.GetIamPolicyRequest{}).Context(ctx).Do()
}

// SetPolicyOrganization sets an IAM policy for the given organization resource.
func (c *CloudResourceManager) SetPolicyOrganization(ctx context.Context, organizationID string, p *crm.Policy) (*crm.Policy, error) {
	if mode.DryRun() {
		log.Println("[DRY_RUN] set policy ", p, " on organization ", organizationID)
		return nil, nil
	}
	return c.service.Organizations.SetIamPolicy(organizationID, &crm.SetIamPolicyRequest{Policy: p}).Context(ctx).Do()
}

// GetOrganization returns the organization info.
func (c *CloudResourceManager) GetOrganization(ctx context.Context, organizationID string) (*crm.Organization, error) {
	return c.service.Organizations.Get(organizationID).Context(ctx).Do()
}
