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
	switch finding.GetFinding().GetCategory() {
	case "PUBLIC_IP_ADDRESS":
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
		r.InstanceZone = sha.Zone(finding.GetFinding().GetResourceName())
		r.InstanceID = sha.Instance(finding.GetFinding().GetResourceName())
	default:
		return nil, entities.ErrUnsupportedFinding
	}
	if r.ProjectID == "" || r.InstanceZone == "" || r.InstanceID == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
}

// Execute removes the public IP of a GCE instance.
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	resources := ent.Configuration.RemovePublicIP.Resources
	return ent.Resource.IfProjectWithinResources(ctx, resources, required.ProjectID, func() error {
		if err := ent.Host.RemoveExternalIPs(ctx, required.ProjectID, required.InstanceZone, required.InstanceID); err != nil {
			return errors.Wrap(err, "failed to remove public ip")
		}
		ent.Logger.Info("removed public IP address for instance %q, in zone %q in project %q.", required.InstanceID, required.InstanceZone, required.ProjectID)
		return nil
	})
}
