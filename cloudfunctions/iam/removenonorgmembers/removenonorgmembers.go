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

	"github.com/googlecloudplatform/security-response-automation/services"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID    string
	AllowDomains []string
	DryRun       bool
}

// Services contains the services needed for this function.
type Services struct {
	Logger   *services.Logger
	Resource *services.Resource
}

// Execute removes all users from a specific project not in allowed domain list.
func Execute(ctx context.Context, values *Values, services *Services) error {
	if values.DryRun {
		services.Logger.Info("dry run, would have removed users not from %q in %q", values.AllowDomains, values.ProjectID)
		return nil
	}
	removed, err := services.Resource.ProjectOnlyKeepUsersFromDomains(ctx, values.ProjectID, values.AllowDomains)
	if err != nil {
		return err
	}
	services.Logger.Info("successfully removed %q from %s", removed, values.ProjectID)
	return nil
}
