package closecloudsql

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
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID, InstanceName string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.SqlScanner
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "PUBLIC_SQL_INSTANCE":
		r.InstanceName = sha.Instance(finding.GetFinding().GetResourceName())
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
	}
	if r.InstanceName == "" || r.ProjectID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute will remove any public ips in sql instance found within the provided folders.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	r := remove(ctx, required, ent.Logger, ent.CloudSQL)
	if err := ent.Resource.IfProjectInFolders(ctx, ent.Configuration.CloseCloudSql.Resources.FolderIDs, required.ProjectID, r); err != nil {
		return errors.Wrap(err, "folders failed")
	}

	if err := ent.Resource.IfProjectInProjects(ctx, ent.Configuration.CloseCloudSql.Resources.ProjectIDs, required.ProjectID, r); err != nil {
		return errors.Wrap(err, "projects failed")
	}
	return nil
}

func remove(ctx context.Context, required *Required, logr *entities.Logger, sql *entities.CloudSQL) func() error {
	return func() error {
		log.Printf("getting details from sql instance %q in project %q.", required.InstanceName, required.ProjectID)
		instance, err := sql.InstanceDetails(ctx, required.ProjectID, required.InstanceName)
		if err != nil {
			return err
		}
		op, err := sql.ClosePublicAccess(ctx, required.ProjectID, required.InstanceName, instance)
		if err != nil {
			return err
		}
		if errs := sql.Wait(required.ProjectID, op); len(errs) > 0 {
			return errs[0]
		}
		logr.Info("removed public access from sql instance %q in project %q.", required.InstanceName, required.ProjectID)
		return nil
	}
}
