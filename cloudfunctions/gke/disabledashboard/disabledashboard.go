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
<<<<<<< HEAD
	default:
		return nil, entities.ErrUnsupportedFinding
=======
>>>>>>> 8a7432ce21d4d9e9221a655d9a2905020835022e
	}
	if r.ProjectID == "" || r.Zone == "" || r.ClusterID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute disables the Kubernetes dashboard.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	resources := ent.Configuration.DisableDashboard.Resources
	return ent.Resource.IfProjectWithinResources(ctx, resources, required.ProjectID, func() error {
		if _, err := ent.Container.DisableDashboard(ctx, required.ProjectID, required.Zone, required.ClusterID); err != nil {
			return err
		}
		ent.Logger.Info("successfully disabled dashboard from cluster %q in project %q", required.ClusterID, required.ProjectID)
		return nil
	})
}
