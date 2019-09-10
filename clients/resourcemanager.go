/*
Package clients provides the required clients for taking automated actions.

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
package clients

import (
	"fmt"

	"google.golang.org/api/cloudresourcemanager/v1"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/option"
)

// CloudResourceManager is the interface used by CRM.
type CloudResourceManager interface {
	GetPolicyProject(string) (*crm.Policy, error)
	SetPolicyProject(string, *crm.Policy) (*crm.Policy, error)
	GetProjectAncestry(string) ([]string, error)
}

// InstantiateCRM initalizes the CRM client.
func InstantiateCRM(c *Client) error {
	crm, err := crm.NewService(c.ctx, option.WithCredentialsFile(authFile))

	if err != nil {
		return fmt.Errorf("failed to init crm: %q", err)
	}
	c.crm = crm
	return nil
}

// GetPolicyProject returns the IAM policy for the given project resource.
func (c *Client) GetPolicyProject(projectID string) (*cloudresourcemanager.Policy, error) {
	rb := &cloudresourcemanager.GetIamPolicyRequest{}
	resp, err := c.crm.Projects.GetIamPolicy(projectID, rb).Context(c.ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get project IAM policy:%q", err)
	}
	return resp, nil
}

// SetPolicyProject sets an IAM policy for the given project resource.
func (c *Client) SetPolicyProject(projectID string, p *cloudresourcemanager.Policy) (*cloudresourcemanager.Policy, error) {
	rb := &cloudresourcemanager.SetIamPolicyRequest{Policy: p}
	resp, err := c.crm.Projects.SetIamPolicy(projectID, rb).Context(c.ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to set project IAM policy:%q", err)
	}
	return resp, nil
}

// GetProjectAncestry returns the folder of the resource ancestry.
func (c *Client) GetProjectAncestry(projectID string) ([]string, error) {
	rb := &cloudresourcemanager.GetAncestryRequest{}
	resp, err := c.crm.Projects.GetAncestry(projectID, rb).Context(c.ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to getAncestry: %q", err)
	}
	s := []string{}
	for _, a := range resp.Ancestor {
		s = append(s, a.ResourceId.Type+"s/"+a.ResourceId.Id)
	}
	return s, nil
}
