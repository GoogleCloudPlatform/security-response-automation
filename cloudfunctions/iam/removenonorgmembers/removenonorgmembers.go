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
	"log"
	"regexp"
	"strings"

	pb "github.com/googlecloudplatform/threat-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/googlecloudplatform/threat-automation/services"
	"github.com/pkg/errors"
	"google.golang.org/api/cloudresourcemanager/v1"
)

// Values contains the required values needed for this function.
type Values struct {
	orgID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Resource      *services.Resource
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.IamScanner
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "NON_ORG_IAM_MEMBER":
		r.orgID = sha.OrgID(finding.GetFinding().GetParent())
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.orgID == "" {
		return nil, services.ErrValueNotFound
	}
	return r, nil
}

// Execute removes non-organization members.
func Execute(ctx context.Context, values *Values, services *Services) error {
	conf := services.Configuration
	allowedDomains := conf.RemoveNonOrgMembers.AllowDomains
	organization, err := services.Resource.Organization(ctx, values.orgID)
	if err != nil {
		return errors.Wrapf(err, "failed to get organization: %s", values.orgID)
	}
	policy, err := services.Resource.PolicyOrganization(ctx, organization.Name)
	if err != nil {
		return errors.Wrap(err, "failed to retrieve organization policy")
	}
	membersToRemove := filterNonOrgMembers(organization.DisplayName, policy.Bindings, allowedDomains)
	if _, err = services.Resource.RemoveMembersOrganization(ctx, organization.Name, membersToRemove, policy); err != nil {
		return errors.Wrap(err, "failed to remove organization policy")
	}
	log.Printf("removed members: %s", membersToRemove)
	return nil
}

func filterNonOrgMembers(orgDisplayName string, bindings []*cloudresourcemanager.Binding, allowedDomains []string) []string {
	regex, _ := regexp.Compile("^.+@" + orgDisplayName + "$")
	var nonOrgMembers []string
	for _, b := range bindings {
		for _, m := range b.Members {
			inOrg := regex.MatchString(m)
			if strings.HasPrefix(m, "user:") && !inOrg && !allowed(m, allowedDomains) {
				nonOrgMembers = append(nonOrgMembers, m)
			}
		}
	}
	return nonOrgMembers
}

// allowed returns a boolean if the member's email address matches one of the domain regular expressions.
func allowed(member string, domains []string) bool {
	for _, d := range domains {
		if matches, _ := regexp.MatchString(d, member); matches {
			return true
		}
	}
	return false
}
