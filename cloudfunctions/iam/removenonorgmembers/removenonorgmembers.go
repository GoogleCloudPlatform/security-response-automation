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
	"encoding/json"
	"strings"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required values needed for this function.
type Values struct {
	OrgID, ProjectID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.IamScanner
	v := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "NON_ORG_IAM_MEMBER":
		if sha.IgnoreFinding(finding.GetFinding()) {
			return nil, services.ErrUnsupportedFinding
		}
		if fromOrg(finding.GetFinding().GetResourceName()) {
			v.OrgID = sha.OrganizationID(finding.GetFinding().GetParent())
		}
		if fromProject(finding.GetFinding().GetResourceName()) {
			v.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
			v.OrgID = sha.OrganizationID(finding.GetFinding().GetParent())
		}
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if v.OrgID == "" && v.ProjectID == "" {
		return nil, services.ErrValueNotFound
	}
	return v, nil
}

// Execute removes non-organization members.
func Execute(ctx context.Context, values *Values, services *Services) error {
	conf := services.Configuration
	allowedDomains := conf.RemoveNonOrgMembers.AllowDomains
	resources := services.Configuration.RemoveNonOrgMembers.Resources
	var membersToRemove []string
	if values.OrgID != "" {
		organization, err := services.Resource.Organization(ctx, values.OrgID)
		if err != nil {
			return errors.Wrapf(err, "failed to get organization: %s", values.OrgID)
		}
		allowedDomains = append(allowedDomains, organization.DisplayName)
		membersToRemove, err = services.Resource.RemoveMembersOrganization(ctx, organization.Name, allowedDomains)
		if err != nil {
			return errors.Wrap(err, "failed to remove organization policy")
		}
	}
	if values.ProjectID != "" && values.OrgID != "" {
		return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
			organization, err := services.Resource.Organization(ctx, values.OrgID)
			if err != nil {
				return errors.Wrapf(err, "failed to get organization: %s", values.OrgID)
			}
			allowedDomains = append(allowedDomains, organization.DisplayName)
			membersToRemove, err = services.Resource.RemoveMembersProjectNotAllowed(ctx, values.ProjectID, allowedDomains)
			if err != nil {
				return errors.Wrap(err, "failed to remove project policy")
			}
			return nil
		})
	}
	services.Logger.Info("removed members: %s", membersToRemove)
	return nil
}

func fromProject(resourceName string) bool {
	return strings.Contains(resourceName, "cloudresourcemanager.googleapis.com/projects")
}

func fromOrg(resourceName string) bool {
	return strings.Contains(resourceName, "cloudresourcemanager.googleapis.com/organizations")
}
