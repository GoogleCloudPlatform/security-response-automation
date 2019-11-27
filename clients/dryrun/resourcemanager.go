package dryrun

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
	"log"

	"github.com/googlecloudplatform/security-response-automation/clients"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

// CloudResourceManager client.
type CloudResourceManager struct {
	serviceClient *clients.CloudResourceManager
}

// NewDryRunCloudResourceManager returns and initalizes the Cloud Resource Manager client.
func NewDryRunCloudResourceManager(original *clients.CloudResourceManager) (*CloudResourceManager, error) {
	return &CloudResourceManager{serviceClient: original}, nil
}

// GetPolicyProject returns the IAM policy for the given project resource.
func (c *CloudResourceManager) GetPolicyProject(ctx context.Context, projectID string) (*crm.Policy, error) {
	return c.serviceClient.GetPolicyProject(ctx, projectID)
}

// SetPolicyProject sets an IAM policy for the given project resource.
func (c *CloudResourceManager) SetPolicyProject(ctx context.Context, projectID string, p *crm.Policy) (*crm.Policy, error) {
	log.Printf("dry_run on, would call 'SetPolicyProject' with params projectID: %q, Policy: %+v", projectID, p)
	return p, nil
}

// SetPolicyProjectWithMask sets an IAM policy for the given project resource.
func (c *CloudResourceManager) SetPolicyProjectWithMask(ctx context.Context, projectID string, p *crm.Policy, updateField ...string) (*crm.Policy, error) {
	log.Printf("dry_run on, would call 'SetPolicyProjectWithMask' with params projectID: %q, Policy: %+v, updateField: %+v", projectID, p, updateField)
	return p, nil
}

// GetAncestry returns the ancestry for the given project.
func (c *CloudResourceManager) GetAncestry(ctx context.Context, projectID string) (*crm.GetAncestryResponse, error) {
	return c.serviceClient.GetAncestry(ctx, projectID)
}

// GetPolicyOrganization returns the IAM policy for the given organization resource.
func (c *CloudResourceManager) GetPolicyOrganization(ctx context.Context, name string) (*crm.Policy, error) {
	return c.serviceClient.GetPolicyOrganization(ctx, name)
}

// SetPolicyOrganization sets an IAM policy for the given organization resource.
func (c *CloudResourceManager) SetPolicyOrganization(ctx context.Context, name string, p *crm.Policy) (*crm.Policy, error) {
	log.Printf("dry_run on, would call 'SetPolicyOrganization' with params name: %q, Policy: %+v", name, p)
	return p, nil
}

// GetOrganization returns the organization info by resource name.
func (c *CloudResourceManager) GetOrganization(ctx context.Context, name string) (*crm.Organization, error) {
	return c.serviceClient.GetOrganization(ctx, name)
}
