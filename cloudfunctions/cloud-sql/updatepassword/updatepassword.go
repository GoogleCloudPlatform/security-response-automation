package updatepassword

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

	srv "github.com/googlecloudplatform/security-response-automation/services"
)

// Values contains the values values needed for this function.
type Values struct {
	ProjectID, InstanceName string
	DryRun                  bool
}

// Services contains the services needed for this function.
type Services struct {
	CloudSQL *srv.CloudSQL
	Resource *srv.Resource
	Logger   *srv.Logger
}

const (
	// hostWildcard matches any MySQL host. Reference: https://cloud.google.com/sql/docs/mysql/users.
	hostWildcard = "%"
	// userName is the MySQL user name that will have their password reset.
	userName = "root"
)

// Execute will update the root password for the MySQL instance found within the provided resources.
func Execute(ctx context.Context, values *Values, services *Services) error {
	log.Printf("updating root password for MySQL instance %q in project %q.", values.InstanceName, values.ProjectID)
	if values.DryRun {
		services.Logger.Info("dry_run on, would have updated root password for MySQL instance %q in project %q.", values.InstanceName, values.ProjectID)
		return nil
	}
	password, err := srv.GeneratePassword()
	if err != nil {
		return err
	}
	if err := services.CloudSQL.UpdateUserPassword(ctx, values.ProjectID, values.InstanceName, hostWildcard, userName, password); err != nil {
		return err
	}
	services.Logger.Info("updated root password for MySQL instance %q in project %q.", values.InstanceName, values.ProjectID)
	return nil
}
