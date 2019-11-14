package disabledashboard

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

	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID, Zone, ClusterID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Container     *services.Container
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.ContainerScanner
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "WEB_UI_ENABLED":
		if sha.IgnoreFinding(finding.GetFinding()) {
			return nil, services.ErrUnsupportedFinding
		}
		r.ProjectID = finding.Finding.SourceProperties.GetProjectID()
		r.Zone = sha.ClusterZone(finding.GetFinding().GetResourceName())
		r.ClusterID = sha.ClusterID(finding.GetFinding().GetResourceName())
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.ProjectID == "" || r.Zone == "" || r.ClusterID == "" {
		return nil, services.ErrValueNotFound
	}
	return r, nil
}

// Execute disables the Kubernetes dashboard.
func Execute(ctx context.Context, values *Values, service *Services) error {
	conf := service.Configuration
	resources := service.Configuration.DisableDashboard.Resources
	return service.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
		if conf.DisableDashboard.Mode == "DRY_RUN" {
			service.Logger.Info("dry_run on, would have disabled dashboard from custer %q in zone %q in project %q", values.ClusterID, values.Zone, values.ProjectID)
			return nil
		}
		if _, err := service.Container.DisableDashboard(ctx, values.ProjectID, values.Zone, values.ClusterID); err != nil {
			return err
		}
		service.Logger.Info("successfully disabled dashboard from cluster %q in project %q", values.ClusterID, values.ProjectID)
		return nil
	})
}
