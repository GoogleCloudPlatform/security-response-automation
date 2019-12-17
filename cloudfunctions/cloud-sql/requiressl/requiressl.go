package requiressl

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
	ProjectID, InstanceName string
	DryRun                  bool
}

// Services contains the services needed for this function.
type Services struct {
	CloudSQL *services.CloudSQL
	Resource *services.Resource
	Logger   *services.Logger
}

// Execute will remove any public ips in sql instance found within the provided folders.
func Execute(ctx context.Context, values *Values, services *Services) error {
	if values.DryRun {
		services.Logger.Info("dry_run on, enforced ssl on sql instance %q in project %q.", values.InstanceName, values.ProjectID)
		return nil
	}
	if err := services.CloudSQL.RequireSSL(ctx, values.ProjectID, values.InstanceName); err != nil {
		return err
	}
	services.Logger.Info("enforced ssl on sql instance %q in project %q.", values.InstanceName, values.ProjectID)
	return nil
}
