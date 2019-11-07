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

	pb "github.com/googlecloudplatform/threat-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/entities/helpers"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID, InstanceName, Host, UserName, Password string
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
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.SqlScanner
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	if finding.GetFinding().GetCategory() == "SQL_NO_ROOT_PASSWORD" {
		r.InstanceName = sha.Instance(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
		r.Host = host
		r.UserName = userName
		pw, err := helpers.GeneratePassword()
		if err != nil {
			return nil, err
		}
		r.Password = pw
	}
	if r.InstanceName == "" || r.ProjectID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute will update the root password in a MySQL instance found within the provided resources.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	resources := ent.Configuration.UpdatePassword.Resources
	return ent.Resource.IfProjectWithinResources(ctx, resources, required.ProjectID, func() error {
		log.Printf("updating root password for sql instance %q in project %q.", required.InstanceName, required.ProjectID)
		op, err := ent.CloudSQL.UpdateUserPassword(ctx, required.ProjectID, required.InstanceName, required.Host, required.UserName, required.Password)
		if err != nil {
			return err
		}
		if errs := ent.CloudSQL.Wait(required.ProjectID, op); len(errs) > 0 {
			return errs[0]
		}
		ent.Logger.Info("updated root password for sql instance %q in project %q.", required.InstanceName, required.ProjectID)
		return nil
	})
}
