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
	"encoding/json"
	"log"

	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the values values needed for this function.
type Values struct {
	ProjectID, InstanceName, Host, UserName, Password string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	CloudSQL      *services.CloudSQL
	Resource      *services.Resource
	Logger        *services.Logger
}

const (
	// hostWildcard matches any MySQL host. Reference: https://cloud.google.com/sql/docs/mysql/users.
	hostWildcard = "%"
	// userName is the MySQL user name that will have their password reset.
	userName = "root"
)

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.SqlScanner
	password, err := services.GeneratePassword()
	if err != nil {
		return nil, err
	}
	values := &Values{
		Host:     hostWildcard,
		UserName: userName,
		Password: password,
	}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "SQL_NO_ROOT_PASSWORD":
		values.InstanceName = sha.Instance(finding.GetFinding().GetResourceName())
		values.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if values.InstanceName == "" || values.ProjectID == "" {
		return nil, services.ErrValueNotFound
	}
	return values, nil
}

// Execute will update the root password for the MySQL instance found within the provided resources.
func Execute(ctx context.Context, values *Values, services *Services) error {
	conf := services.Configuration
	resources := services.Configuration.UpdatePassword.Resources
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
		log.Printf("updating root password for MySQL instance %q in project %q.", values.InstanceName, values.ProjectID)
		if conf.UpdatePassword.Mode == "DRY_RUN" {
			services.Logger.Info("dry_run on, would have updated root password for MySQL instance %q in project %q.", values.InstanceName, values.ProjectID)
			return nil
		}
		if err := services.CloudSQL.UpdateUserPassword(ctx, values.ProjectID, values.InstanceName, values.Host, values.UserName, values.Password); err != nil {
			return err
		}
		services.Logger.Info("updated root password for MySQL instance %q in project %q.", values.InstanceName, values.ProjectID)
		return nil
	})
}
