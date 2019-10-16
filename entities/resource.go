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
	"fmt"
	"regexp"
	"strings"

	"cloud.google.com/go/iam"
	"github.com/pkg/errors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

type crmClient interface {
	GetAncestry(context.Context, string) (*crm.GetAncestryResponse, error)
	SetPolicyProject(context.Context, string, *crm.Policy) (*crm.Policy, error)
	GetPolicyProject(context.Context, string) (*crm.Policy, error)
	GetPolicyOrganization(context.Context, string) (*crm.Policy, error)
	SetPolicyOrganization(context.Context, string, *crm.Policy) (*crm.Policy, error)
	GetOrganization(context.Context, string) (*crm.Organization, error)
}

type storageClient interface {
	SetBucketPolicy(context.Context, string, *iam.Policy) error
	BucketPolicy(context.Context, string) (*iam.Policy, error)
}

// Resource entity.
type Resource struct {
	crm     crmClient
	storage storageClient
}

// NewResource returns a new resource entity.
func NewResource(crm crmClient, s storageClient) *Resource {
	return &Resource{
		crm:     crm,
		storage: s,
	}
}

// RemoveDomainsProject removes all members from the given project that end with the disallowed domains.
func (r *Resource) RemoveDomainsProject(ctx context.Context, projectID string, disallowedDomains []string) (*crm.Policy, error) {
	domains := strings.Replace(strings.Join(disallowedDomains, "|"), ".", `\.`, -1)
	regex, err := regexp.Compile(fmt.Sprintf(`@(%s)$`, domains))
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %q", err)
	}

	resp, err := r.crm.GetPolicyProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project policy: %q", err)
	}

	p := r.removeMembersFromPolicy(regex, resp)

	setp, err := r.crm.SetPolicyProject(ctx, projectID, p)
	if err != nil {
		return nil, fmt.Errorf("failed to set project policy: %q", err)
	}
	return setp, nil
}

// RemoveMembersProject removes the given members from the project.
func (r *Resource) RemoveMembersProject(ctx context.Context, projectID string, remove []string) (*crm.Policy, error) {
	j := strings.Replace(strings.Join(remove, "|"), ".", `\.`, -1)
	e, err := regexp.Compile("^" + j + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %q", err)
	}
	resp, err := r.crm.GetPolicyProject(ctx, projectID)

	if err != nil {
		return nil, fmt.Errorf("failed to get project policy: %q", err)
	}

	p := r.removeMembersFromPolicy(e, resp)
	s, err := r.crm.SetPolicyProject(ctx, projectID, p)
	if err != nil {
		return nil, fmt.Errorf("failed to set project policy: %q", err)
	}
	return s, nil
}

// RemoveMembersFromBucket removes members from the bucket.
func (r *Resource) RemoveMembersFromBucket(ctx context.Context, bucketName string, members []string) error {
	p, err := r.storage.BucketPolicy(ctx, bucketName)
	if err != nil {
		return err
	}
	// Save what we need to remove in a map so we don't mutate a slice while we iterate over it.
	toRemove := make(map[iam.RoleName]map[string]bool)

	for _, role := range p.Roles() {
		for _, policyMember := range p.Members(role) {
			for _, m := range members {
				if policyMember != m {
					continue
				}
				if toRemove[role] == nil {
					toRemove[role] = make(map[string]bool)
				}
				toRemove[role][m] = true
			}
		}
	}

	for k, v := range toRemove {
		for kk := range v {
			p.Remove(kk, k)
		}
	}
	return r.storage.SetBucketPolicy(ctx, bucketName, p)
}

// GetProjectAncestry returns a slice of the project's ancestry.
func (r *Resource) GetProjectAncestry(ctx context.Context, projectID string) ([]string, error) {
	resp, err := r.crm.GetAncestry(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to project ancestry: %q", err)
	}
	s := []string{}
	for _, a := range resp.Ancestor {
		s = append(s, a.ResourceId.Type+"s/"+a.ResourceId.Id)
	}
	return s, nil
}

// removeMembersFromPolicy removes members that match the given regex.
func (r *Resource) removeMembersFromPolicy(regex *regexp.Regexp, policy *crm.Policy) *crm.Policy {
	for _, b := range policy.Bindings {
		members := []string{}
		for _, m := range b.Members {
			if !regex.MatchString(m) {
				members = append(members, m)
			}
		}
		b.Members = members
	}
	return policy
}

// RemoveMembersOrganization removes the given members from the organization.
func (r *Resource) RemoveMembersOrganization(ctx context.Context, organizationID string, remove []string, p *crm.Policy) (*crm.Policy, error) {
	j := strings.Replace(strings.Join(remove, "|"), ".", `\.`, -1)
	e, err := regexp.Compile("^" + j + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %q", err)
	}
	newPolicy := r.removeMembersFromPolicy(e, p)
	s, err := r.crm.SetPolicyOrganization(ctx, organizationID, newPolicy)
	if err != nil {
		return nil, fmt.Errorf("failed to set project policy: %q", err)
	}
	return s, nil
}

// PolicyOrganization returns the IAM policy for the given organization resource.
func (r *Resource) PolicyOrganization(ctx context.Context, organizationID string) (*crm.Policy, error) {
	return r.crm.GetPolicyOrganization(ctx, organizationID)
}

// Organization returns the organization name for the given organization resource.
func (r *Resource) Organization(ctx context.Context, organizationID string) (*crm.Organization, error) {
	return r.crm.GetOrganization(ctx, organizationID)
}

// IfProjectInFolders will apply the function if the project ID is within the folder IDs.
func (r *Resource) IfProjectInFolders(ctx context.Context, ids []string, projectID string, fn func() error) error {
	if len(ids) == 0 {
		return nil
	}
	ancestors, err := r.GetProjectAncestry(ctx, projectID)
	if err != nil {
		return errors.Wrap(err, "failed to get project ancestry")
	}
	for _, resource := range ancestors {
		for _, folderID := range ids {
			if resource != "folders/"+folderID {
				continue
			}
			if err := fn(); err != nil {
				return err
			}
		}
	}
	return nil
}

// IfProjectInProjects will apply the function if the project ID is within the project IDs.
func (r *Resource) IfProjectInProjects(_ context.Context, _ []string, _ string, _ func() error) error {
	return nil
}
