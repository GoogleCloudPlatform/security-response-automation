// Package revoke provides the implementation of automated actions.
package revoke

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
	"fmt"
	"regexp"
	"strings"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID       string
	ExternalMembers []string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.AnomalousIAMGrant
	v := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetJsonPayload().GetDetectionCategory().GetSubRuleName() {
	case "external_member_added_to_policy":
		v.ProjectID = finding.GetJsonPayload().GetProperties().GetProjectId()
		v.ExternalMembers = finding.GetJsonPayload().GetProperties().GetExternalMembers()
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if v.ProjectID == "" || len(v.ExternalMembers) == 0 {
		return nil, services.ErrValueNotFound
	}
	return v, nil
}

// Execute is the entry point for the IAM revoker Cloud Function.
//
// This automation will remove users from a project's policy if:
// - The users are believed to be external as reported from the finding provider.
// - The project where the external users were found are within the set configured resources.
// - The users do not match the list of allowed domains.
//
func Execute(ctx context.Context, values *Values, services *Services) error {
	conf := services.Configuration.RevokeGrants
	members, err := toRemove(values.ExternalMembers, conf.AllowDomains)
	if err != nil {
		return err
	}
	return services.Resource.CheckMatches(ctx, conf.Target, conf.Exclude, values.ProjectID, func() error {
		if conf.DryRun {
			services.Logger.Info("dry_run on, would have removed %q from %q", members, values.ProjectID)
			return nil
		}
		if err := services.Resource.RemoveUsersProject(ctx, values.ProjectID, members); err != nil {
			return err
		}
		services.Logger.Info("successfully removed %q from %s", members, values.ProjectID)
		return nil
	})
}

// toRemove returns a slice containing only external members that are disallowed.
// This check is done to ensure we only consider removing members that came from the finding and not
// just any members that aren't part of the configured allow list.
func toRemove(members []string, allowed []string) ([]string, error) {
	allowedList := strings.Replace(strings.Join(allowed, "|"), ".", `\.`, -1)
	allowedRegExp, err := regexp.Compile("^.+@" + allowedList + "$")
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex: %q", err)
	}
	remove := []string{}
	for _, user := range members {
		if allowedRegExp.MatchString(user) {
			continue
		}
		remove = append(remove, user)

	}
	return remove, nil
}
