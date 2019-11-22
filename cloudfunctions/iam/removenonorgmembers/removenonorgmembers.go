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

	pb "github.com/googlecloudplatform/security-response-automation/compiled/scc/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/scc"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

const projectPrefix = "//cloudresourcemanager.googleapis.com/projects/"

// Values contains the required values needed for this function.
type Values struct {
	ProjectID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Logger        *services.Logger
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
		if scc.IgnoreFinding(finding.GetFinding()) {
			return nil, services.ErrUnsupportedFinding
		}
		if fromProject(finding.GetFinding().GetResourceName()) {
			v.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
		}
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if v.ProjectID == "" {
		return nil, services.ErrValueNotFound
	}
	return v, nil
}

// Execute removes all users from a specific project not in allowed domain list.
func Execute(ctx context.Context, values *Values, services *Services) error {
	conf := services.Configuration.RemoveNonOrgMembers
	return services.Resource.IfProjectWithinResources(ctx, conf.Resources, values.ProjectID, func() error {
		if conf.DryRun {
			services.Logger.Info("dry run, would have removed users not from %q in %q", conf.AllowDomains, values.ProjectID)
			return nil
		}
		removed, err := services.Resource.ProjectOnlyKeepUsersFromDomains(ctx, values.ProjectID, conf.AllowDomains)
		if err != nil {
			return err
		}
		services.Logger.Info("successfully removed %q from %s", removed, values.ProjectID)
		return nil
	})
}

func fromProject(resourceName string) bool {
	return strings.HasPrefix(resourceName, projectPrefix)
}
