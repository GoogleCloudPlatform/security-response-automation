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

	pb "github.com/googlecloudplatform/threat-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/googlecloudplatform/threat-automation/services"
	"github.com/googlecloudplatform/threat-automation/services/helpers"
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
	// defaultHostName is the host name of the MySQL instance.
	// The % sign is a wildcard that matches any host. More information
	// in the official documentation: https://cloud.google.com/sql/docs/mysql/users.
	host = "%"
	// userName is the MySQL user name that will have their password reset.
	userName = "root"
)

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.SqlScanner
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "SQL_NO_ROOT_PASSWORD":
		r.InstanceName = sha.Instance(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
		r.Host = host
		r.UserName = userName
		pw, err := helpers.GeneratePassword()
		if err != nil {
			return nil, err
		}
		r.Password = pw
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.InstanceName == "" || r.ProjectID == "" {
		return nil, services.ErrValueNotFound
	}
	return r, nil
}

// Execute will update the root password in a MySQL instance found within the provided resources.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.UpdatePassword.Resources
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
		services.Logger.Info("updating root password for sql instance %q in project %q.", values.InstanceName, values.ProjectID)
		op, err := services.CloudSQL.UpdateUserPassword(ctx, values.ProjectID, values.InstanceName, values.Host, values.UserName, values.Password)
		if err != nil {
			return err
		}
		if errs := services.CloudSQL.Wait(values.ProjectID, op); len(errs) > 0 {
			return errs[0]
		}
		services.Logger.Info("updated root password for sql instance %q in project %q.", values.InstanceName, values.ProjectID)
		return nil
	})
}
