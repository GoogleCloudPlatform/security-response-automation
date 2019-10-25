package disabledashboard

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
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/sha"
	"github.com/pkg/errors"
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID, Zone, ClusterID string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.ContainerScanner
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "WEB_UI_ENABLED":
		r.ProjectID = finding.Finding.SourceProperties.GetProjectID()
		r.Zone = sha.ClusterZone(finding.GetFinding().GetResourceName())
		r.ClusterID = sha.ClusterID(finding.GetFinding().GetResourceName())
	}
	if r.ProjectID == "" || r.Zone == "" || r.ClusterID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute will remove any public users from buckets found within the provided folders.
func Execute(ctx context.Context, req *Required, ent *entities.Entity) error {
	folders := ent.Configuration.DisableDashboard.Resources.FolderIDs
	projects := ent.Configuration.DisableDashboard.Resources.ProjectIDs
	r := disableDashboard(ctx, req, ent.Logger, ent.Container)
	if err := ent.Resource.IfProjectInFolders(ctx, folders, req.ProjectID, r); err != nil {
		return err
	}
	if err := ent.Resource.IfProjectInProjects(ctx, projects, req.ProjectID, r); err != nil {
		return err
	}
	return nil
}

func disableDashboard(ctx context.Context, req *Required, log *entities.Logger, cont *entities.Container) func() error {
	return func() error {
		log.Info("Disabling dashboard from cluster")
		if resp, err := cont.DisableDashboard(ctx, req.ProjectID, req.Zone, req.ClusterID); err != nil {
			return err
		} else {
			log.Info("Response: %v", resp)
		}
		log.Info("Successfully disabled dashboard from cluster %s in project %s", req.ClusterID, req.ProjectID)
		return nil
	}
}
