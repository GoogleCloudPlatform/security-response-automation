package enableauditlogs

//  Copyright 2019 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  	https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

import (
	"context"

	"github.com/googlecloudplatform/security-response-automation/services"
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID string
}

// Services contains the services needed for this function.
type Services struct {
	Resource *services.Resource
	Logger   *services.Logger
}

// Values contains the required values needed for this function.
type Values struct {
	ProjectID string
	DryRun    bool
}

// Execute is the entry point for the Cloud Function to enable audit logs for a specific project.
func Execute(ctx context.Context, values *Values, services *Services) error {
	if values.DryRun {
		services.Logger.Info("dry_run on, would have enabled data access audit logs in project %q", values.ProjectID)
		return nil
	}
	if _, err := services.Resource.EnableAuditLogs(ctx, values.ProjectID); err != nil {
		return err
	}
	services.Logger.Info("audit logs was enabled on %q", values.ProjectID)
	return nil
}
