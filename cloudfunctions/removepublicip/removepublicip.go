package removepublicip

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
	"encoding/json"

	pb "github.com/googlecloudplatform/threat-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"

	"github.com/pkg/errors"
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID, InstanceZone, InstanceID string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.ComputeInstanceScanner
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}

	if finding.GetFinding().GetCategory() == "PUBLIC_IP_ADDRESS" {
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
		r.InstanceZone = sha.Zone(finding.GetFinding().GetResourceName())
		r.InstanceID = sha.Instance(finding.GetFinding().GetResourceName())
	}

	if r.ProjectID == "" || r.InstanceZone == "" || r.InstanceID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute the removal of public IP addresses in a GCE instance.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	folders := ent.Configuration.RemovePublicIP.Resources.FolderIDs
	projects := ent.Configuration.RemovePublicIP.Resources.ProjectIDs
	r := removePublicIP(ctx, ent.Logger, ent.Host, required.ProjectID, required.InstanceZone, required.InstanceID)
	if err := ent.Resource.IfProjectInFolders(ctx, folders, required.ProjectID, r); err != nil {
		return err
	}
	if err := ent.Resource.IfProjectInProjects(ctx, projects, required.ProjectID, r); err != nil {
		return err
	}
	return nil
}

func removePublicIP(ctx context.Context, logr *entities.Logger, host *entities.Host, projectID, instanceZone, instanceID string) func() error {
	return func() error {
		if err := host.RemoveExternalIPs(ctx, projectID, instanceZone, instanceID); err != nil {
			return errors.Wrap(err, "failed to remove public ip:")
		}
		logr.Info("removed ip addresses for instance %q, in zone %q in project %q.", instanceID, instanceZone, projectID)
		return nil
	}
}
