package services

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
	SetPolicyProjectWithMask(context.Context, string, *crm.Policy, ...string) (*crm.Policy, error)
}

type storageClient interface {
	SetBucketPolicy(context.Context, string, *iam.Policy) error
	BucketPolicy(context.Context, string) (*iam.Policy, error)
	EnableBucketOnlyPolicy(context.Context, string) error
}

// Resource service.
type Resource struct {
	crm     crmClient
	storage storageClient
}

// NewResource returns a new resource service.
func NewResource(crm crmClient, s storageClient) *Resource {
	return &Resource{
		crm:     crm,
		storage: s,
	}
}

// ProjectOnlyKeepUsersFromDomains removes users from the policy if they do not match the domain. (Non-users are not affected.)
func (r *Resource) ProjectOnlyKeepUsersFromDomains(ctx context.Context, projectID string, allowDomains []string) ([]string, error) {
	existingPolicy, err := r.crm.GetPolicyProject(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to get project policy: %q", err)
	}
	removed, policy, err := r.keepUsersFromPolicy(existingPolicy, allowDomains)
	fmt.Printf("foo: %q\n", allowDomains)
	fmt.Printf("removed: %q\n", removed)
	fmt.Printf("err: %q\n", err)
	if err != nil {
		return nil, err
	}
	if _, err := r.crm.SetPolicyProject(ctx, projectID, policy); err != nil {
		return nil, fmt.Errorf("failed to set project policy: %q", err)
	}
	return removed, nil
}

// RemoveUsersProject removes users from the project.
func (r *Resource) RemoveUsersProject(ctx context.Context, projectID string, remove []string) error {
	existingPolicy, err := r.crm.GetPolicyProject(ctx, projectID)
	if err != nil {
		return fmt.Errorf("failed to get project policy: %q", err)
	}
	policy := r.removeUsersFromPolicy(existingPolicy, remove)
	if _, err := r.crm.SetPolicyProject(ctx, projectID, policy); err != nil {
		return fmt.Errorf("failed to set project policy: %q", err)
	}
	return nil
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

// EnableAuditLogs enable audit logs to all services and LogTypes.
func (r *Resource) EnableAuditLogs(ctx context.Context, projectID string) (*crm.Policy, error) {
	res, err := r.crm.GetPolicyProject(ctx, projectID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get project policy")
	}
	isDefault := false
	enableAll := &crm.AuditConfig{
		AuditLogConfigs: []*crm.AuditLogConfig{
			{LogType: "ADMIN_READ"},
			{LogType: "DATA_READ"},
			{LogType: "DATA_WRITE"},
		},
		Service: "allServices",
	}
	for _, conf := range res.AuditConfigs {
		if conf.Service == "allServices" {
			conf.AuditLogConfigs = enableAll.AuditLogConfigs
			isDefault = true
		}
	}
	if !isDefault {
		res.AuditConfigs = append(res.AuditConfigs, enableAll)
	}

	result, err := r.crm.SetPolicyProjectWithMask(ctx, projectID, res, "auditConfigs")
	if err != nil {
		return nil, errors.Wrap(err, "failed to update project policy")
	}
	return result, nil
}

// GetProjectAncestry returns a slice of the project's ancestry.
func (r *Resource) GetProjectAncestry(ctx context.Context, projectID string) ([]string, error) {
	resp, err := r.crm.GetAncestry(ctx, projectID)
	if err != nil {
		return nil, err
	}
	s := []string{}
	for _, a := range resp.Ancestor {
		s = append(s, a.ResourceId.Type+"s/"+a.ResourceId.Id)
	}
	return s, nil
}

// keepUsersFromPolicy keeps users if they match the given domain.
func (r *Resource) keepUsersFromPolicy(policy *crm.Policy, allowedDomains []string) ([]string, *crm.Policy, error) {
	// Throw an error if no allowed domains are passed. Otherwise all users would be removed.
	if len(allowedDomains) == 0 {
		return nil, nil, errors.New("must provide at least one domain to allow")
	}
	allowed := strings.Replace(strings.Join(allowedDomains, "|"), ".", `\.`, -1)
	allowedRegExp, err := regexp.Compile("^.+@(?:" + allowed + ")$")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compile regex: %q", err)
	}
	removed := []string{}
	for _, b := range policy.Bindings {
		members := []string{}
		for _, member := range b.Members {
			isUser := strings.HasPrefix(member, "user:")
			found := false
			if allowedRegExp.MatchString(member) {
				found = true
			}
			if !isUser || found {
				members = append(members, member)
				continue
			}
			if isUser && !found {
				removed = append(removed, member)
			}
		}
		b.Members = members
	}
	return removed, policy, nil
}

// removeUsersFromPolicy removes a slice of users from a policy
func (r *Resource) removeUsersFromPolicy(policy *crm.Policy, users []string) *crm.Policy {
	for _, b := range policy.Bindings {
		members := []string{}
		for _, member := range b.Members {
			isUser := strings.HasPrefix(member, "user:")
			found := false
			for _, user := range users {
				if user == member {
					found = true
					break
				}
			}
			if !isUser || !found {
				members = append(members, member)
				continue
			}
		}
		b.Members = members
	}
	return policy
}

// removeMembersFromOrgPolicy removes Google account (user:) members that doesn't match the given regex.
func (r *Resource) removeMembersFromOrgPolicy(regex *regexp.Regexp, policy *crm.Policy) (*crm.Policy, []string) {
	membersToRemove := []string{}
	for _, b := range policy.Bindings {
		allowedMembers := []string{}
		for _, m := range b.Members {
			isUser := strings.HasPrefix(m, "user:")
			if !isUser || regex.MatchString(m) {
				allowedMembers = append(allowedMembers, m)
			} else {
				membersToRemove = append(membersToRemove, m)
			}
		}
		b.Members = allowedMembers
	}
	return policy, membersToRemove
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
func (r *Resource) RemoveMembersOrganization(ctx context.Context, displayName, name string, allowed []string, p *crm.Policy) ([]string, error) {
	allowed = append(allowed, displayName)
	j := strings.Replace(strings.Join(allowed, "|"), ".", `\.`, -1)
	e, err := regexp.Compile("^.+@" + j + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %q", err)
	}
	newPolicy, membersToRemove := r.removeMembersFromOrgPolicy(e, p)
	if _, err := r.crm.SetPolicyOrganization(ctx, name, newPolicy); err != nil {
		return membersToRemove, fmt.Errorf("failed to set project policy: %q", err)
	}
	return membersToRemove, nil
}

// PolicyOrganization returns the IAM policy for the given resource name.
func (r *Resource) PolicyOrganization(ctx context.Context, name string) (*crm.Policy, error) {
	return r.crm.GetPolicyOrganization(ctx, name)
}

// Organization returns the organization name for the given organization resource.
func (r *Resource) Organization(ctx context.Context, orgID string) (*crm.Organization, error) {
	return r.crm.GetOrganization(ctx, "organizations/"+orgID)
}

// EnableBucketOnlyPolicy enable bucket only policy for the given bucket
func (r *Resource) EnableBucketOnlyPolicy(ctx context.Context, bucketName string) error {
	return r.storage.EnableBucketOnlyPolicy(ctx, bucketName)
}

// IfProjectWithinResources executes the provided function if the project ID is an ancestor of any provided resources.
func (r *Resource) IfProjectWithinResources(ctx context.Context, conf *Resources, projectID string, fn func() error) error {
	if err := r.IfProjectInFolders(ctx, conf.FolderIDs, projectID, fn); err != nil {
		return err
	}
	if err := r.IfProjectInProjects(ctx, conf.ProjectIDs, projectID, fn); err != nil {
		return err
	}
	if err := r.IfProjectInOrg(ctx, conf.OrganizationID, projectID, fn); err != nil {
		return err
	}
	return nil
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
func (r *Resource) IfProjectInProjects(ctx context.Context, ids []string, projectID string, fn func() error) error {
	if len(ids) == 0 {
		return nil
	}
	for _, v := range ids {
		if v != projectID {
			continue
		}
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

// IfProjectInOrg will apply the function if the project ID is within the organization.
func (r *Resource) IfProjectInOrg(ctx context.Context, orgID, projectID string, fn func() error) error {
	if orgID == "" {
		return nil
	}
	ancestors, err := r.GetProjectAncestry(ctx, projectID)
	if err != nil {
		return errors.Wrap(err, "failed to get project ancestry")
	}
	for _, resource := range ancestors {
		if resource == "organizations/"+orgID {
			if err := fn(); err != nil {
				return err
			}
		}
	}
	return nil
}
