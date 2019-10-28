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

	pb "github.com/googlecloudplatform/threat-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// Required contains the required values needed for this function.
type Required struct {
	OrganizationID string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.IamScanner
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "NON_ORG_IAM_MEMBER":
		r.OrganizationID = sha.OrganizationID(finding.GetFinding().GetParent())
	}
	if r.OrganizationID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute removes non-organization members.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	organization, err := ent.Resource.Organization(ctx, required.OrganizationID)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve organization")
	}
	policy, err := ent.Resource.PolicyOrganization(ctx, organization.Name)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve organization policies")
	}
	membersToRemove := filterNonOrgMembers(organization.DisplayName, policy.Bindings)
	if _, err = ent.Resource.RemoveMembersOrganization(ctx, organization.Name, membersToRemove, policy); err != nil {
		return errors.Wrap(err, "failed to remove organization policies")
	}
	return nil
}

func filterNonOrgMembers(organizationDisplayName string, bindings []*cloudresourcemanager.Binding) (nonOrgMembers []string) {
	for _, b := range bindings {
		for _, m := range b.Members {
			if notFromOrg(m, "user:", organizationDisplayName) {
				nonOrgMembers = append(nonOrgMembers, m)
			}
		}
	}
	return nonOrgMembers
}

func notFromOrg(member, prefix, content string) bool {
	return strings.HasPrefix(member, prefix) && !strings.Contains(member, content)
}
