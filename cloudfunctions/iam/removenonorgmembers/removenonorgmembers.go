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
	v := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "NON_ORG_IAM_MEMBER":
		v.orgID = sha.OrganizationID(finding.GetFinding().GetParent())
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if v.orgID == "" {
		return nil, services.ErrValueNotFound
	}
	return v, nil
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
	membersToRemove, err := filterNonOrgMembers(organization.DisplayName, policy.Bindings, allowedDomains)
	if err != nil {
		return errors.Wrap(err, "failed to filter non-org members")
	}
	if _, err = services.Resource.RemoveMembersOrganization(ctx, organization.Name, membersToRemove, policy); err != nil {
		return errors.Wrap(err, "failed to remove organization policy")
	}
	log.Printf("removed members: %s", membersToRemove)
	return nil
}

func filterNonOrgMembers(orgDisplayName string, bindings []*cloudresourcemanager.Binding, allowedDomains []string) ([]string, error) {
	expr := "^.+@" + orgDisplayName + "$"
	regexOrg, err := regexp.Compile(expr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to apply organization regex %q", expr)
	}
	var regexDomains []regexp.Regexp
	for _, d := range allowedDomains {
		rd, err := regexp.Compile("^.+@" + d + "$")
		if err != nil {
			return nil, errors.Wrapf(err, "failed to apply domain regex %q. Check settings.json", d)
		}
		regexDomains = append(regexDomains, *rd.Copy())
	}
	var nonOrgMembers []string
	for _, b := range bindings {
		for _, m := range b.Members {
			inOrg := regexOrg.MatchString(m)
			isUser := strings.HasPrefix(m, "user:")
			if isUser && !inOrg && !allowed(m, regexDomains) {
				nonOrgMembers = append(nonOrgMembers, m)
			}
		}
	}
	return nonOrgMembers, nil
}

// allowed returns a boolean if the member's email address matches one of the domain regular expressions.
func allowed(member string, regexDomains []regexp.Regexp) bool {
	for i := 0; i < len(regexDomains); i++ {
		if regexDomains[i].MatchString(member) {
			return true
		}
	}
	return false
}
