// Package revokeiam provides the implementation of automated actions.
package revokeiam

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

	pb "github.com/googlecloudplatform/threat-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/pkg/errors"
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID       string
	ExternalMembers []string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.AnomalousIAMGrant
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	switch finding.GetJsonPayload().GetDetectionCategory().GetSubRuleName() {
	case "external_member_added_to_policy":
		r.ProjectID = finding.GetJsonPayload().GetProperties().GetProjectId()
		r.ExternalMembers = finding.GetJsonPayload().GetProperties().GetExternalMembers()
	default:
		return nil, entities.ErrUnsupportedFinding
	}
	if r.ProjectID == "" || len(r.ExternalMembers) == 0 {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute is the entry point for the IAM revoker Cloud Function.
//
// This Cloud Function will read the incoming finding, if it's a supported type of finding that
// indicates an external member was invited to a policy check to see if the external member
// is in a list of disallowed domains.
//
// Additionally, check to see if the affected project is within the configured resources. If the grant
// was to a domain explicitly disallowed and within the parent resource then remove the member from
// the IAM policy for the affected resource.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	conf := ent.Configuration
	resources := ent.Configuration.RevokeGrants.Resources
	members := toRemove(required.ExternalMembers, conf.RevokeGrants.Removelist)
	return ent.Resource.IfProjectWithinResources(ctx, resources, required.ProjectID, func() error {
		if _, err := ent.Resource.RemoveMembersProject(ctx, required.ProjectID, members); err != nil {
			return err
		}
		ent.Logger.Info("successfully removed %q from %s", members, required.ProjectID)
		return nil
	})
}

// toRemove returns a slice containing only external members that are disallowed.
func toRemove(members []string, disallowed []string) []string {
	r := []string{}
	for _, mm := range members {
		for _, d := range disallowed {
			if !strings.HasSuffix(mm, d) {
				continue
			}
			r = append(r, mm)
		}
	}
	return r
}
