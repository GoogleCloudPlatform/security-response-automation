package removenonorgmembers

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

var withPrefixAndNotContains = func(s string, prefix string, content string) bool {
	return strings.HasPrefix(s, prefix) && !strings.Contains(s, content)
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
	membersToRemove := filterNonOrgMembers(organization.DisplayName, policy.Bindings, withPrefixAndNotContains)
	_, err = ent.Resource.RemoveMembersOrganization(ctx, organization.Name, membersToRemove, policy)
	if err != nil {
		return errors.Wrap(err, "failed to remove organization policies")
	}
	return nil
}

func filterNonOrgMembers(organizationDisplayName string, bindings []*cloudresourcemanager.Binding,
	hasPrefixAndNotFromOrganization func(s string, memberPrefix string, organizationDisplayName string) bool) (nonOrgMembers []string) {
	for _, b := range bindings {
		for _, m := range b.Members {
			if hasPrefixAndNotFromOrganization(m, "user:", organizationDisplayName) {
				nonOrgMembers = append(nonOrgMembers, m)
			}
		}
	}
	return nonOrgMembers
}
