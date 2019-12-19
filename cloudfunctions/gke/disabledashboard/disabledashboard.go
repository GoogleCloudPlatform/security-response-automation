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

	"github.com/googlecloudplatform/security-response-automation/services"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID, Zone, ClusterID string
	DryRun                     bool
}

// Services contains the services needed for this function.
type Services struct {
	Container *services.Container
	Resource  *services.Resource
	Logger    *services.Logger
}

// Execute disables the Kubernetes dashboard.
func Execute(ctx context.Context, values *Values, service *Services) error {
	if values.DryRun {
		service.Logger.Info("dry_run on, would have disabled dashboard from custer %q in zone %q in project %q", values.ClusterID, values.Zone, values.ProjectID)
		return nil
	}
	if _, err := service.Container.DisableDashboard(ctx, values.ProjectID, values.Zone, values.ClusterID); err != nil {
		return err
	}
	service.Logger.Info("successfully disabled dashboard from cluster %q in project %q", values.ClusterID, values.ProjectID)
	return nil
}
