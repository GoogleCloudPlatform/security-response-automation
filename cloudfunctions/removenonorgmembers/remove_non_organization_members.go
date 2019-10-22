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
	OrganizationName string
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
		r.OrganizationName = sha.OrganizationID(finding.GetFinding().Parent)
	}
	if r.OrganizationName == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// RemoveNonOrganizationMembers is the entry point of the Cloud Function.
//func RemoveNonOrganizationMembers(ctx context.Context, m pubsub.Message, ent *entities.Entity) error {
//	finding, err := sha.NewFinding(&m)
//	if err != nil {
//		return errors.Wrap(err, "failed to read finding")
//	}
//	organization, err := ent.Resource.Organization(ctx, finding.OrganizationID())
//	if err != nil {
//		return errors.Wrap(err, "failed to retrieve organization")
//	}
//	policy, err := ent.Resource.PolicyOrganization(ctx, organization.Name)
//	if err != nil {
//		return errors.Wrap(err, "failed to retrieve organization policies")
//	}
//	membersToRemove := filterNonOrgMembers(organization.DisplayName, policy.Bindings, withPrefixAndNotContains)
//	_, err = ent.Resource.RemoveMembersOrganization(ctx, organization.Name, membersToRemove, policy)
//	if err != nil {
//		return errors.Wrap(err, "failed to remove organization policies")
//	}
//	return nil
//}

func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	return nil
}

func filterNonOrgMembers(organizationDisplayName string, bindings []*cloudresourcemanager.Binding,
	isNotFromOrganization func(s string, memberPrefix string, organizationDisplayName string) bool) (nonOrgMembers []string) {
	for _, b := range bindings {
		for _, m := range b.Members {
			if isNotFromOrganization(m, "user:", organizationDisplayName) {
				nonOrgMembers = append(nonOrgMembers, m)
			}
		}
	}
	return nonOrgMembers
}

var withPrefixAndNotContains = func(s string, prefix string, content string) bool {
	return strings.HasPrefix(s, prefix) && !strings.Contains(s, content)
}
