package removepublic

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
	"log"

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

// Execute will remove any public IPs in SQL instance found within the provided resources.
func Execute(ctx context.Context, values *Values, services *Services) error {
	log.Printf("getting details from Cloud SQL instance %q in project %q.", values.InstanceName, values.ProjectID)
	instance, err := services.CloudSQL.InstanceDetails(ctx, values.ProjectID, values.InstanceName)
	if err != nil {
		return err
	}

	acls := instance.Settings.IpConfiguration.AuthorizedNetworks
	if !services.CloudSQL.IsPublic(acls) {
		services.Logger.Info("instance %q does not have public access enabled", values.InstanceName)
		return nil
	}
	if values.DryRun {
		services.Logger.Info("dry_run on, would have removed public access from Cloud SQL instance %q in project %q.", values.InstanceName, values.ProjectID)
		return nil
	}
	if err := services.CloudSQL.ClosePublicAccess(ctx, values.ProjectID, values.InstanceName, acls); err != nil {
		return err
	}
	services.Logger.Info("removed public access from Cloud SQL instance %q in project %q.", values.InstanceName, values.ProjectID)
	return nil
}
