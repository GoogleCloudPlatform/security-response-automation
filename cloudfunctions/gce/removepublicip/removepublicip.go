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

	pb "github.com/googlecloudplatform/security-response-automation/compiled/sha/protos"
	"github.com/googlecloudplatform/security-response-automation/providers/sha"
	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID, InstanceZone, InstanceID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	Host          *services.Host
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.ComputeInstanceScanner
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "PUBLIC_IP_ADDRESS":
		if sha.IgnoreFinding(finding.GetFinding()) {
			return nil, services.ErrUnsupportedFinding
		}
		r.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
		r.InstanceZone = sha.Zone(finding.GetFinding().GetResourceName())
		r.InstanceID = sha.Instance(finding.GetFinding().GetResourceName())
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.ProjectID == "" || r.InstanceZone == "" || r.InstanceID == "" {
		return nil, services.ErrValueNotFound
	}
	return r, nil
}

// Execute removes the public IP of a GCE instance.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.RemovePublicIP.Resources
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
		if services.Configuration.RemovePublicIP.Mode == "DRY_RUN" {
			services.Logger.Info("dry_run on, would have removed public IP address for instance %q, in zone %q in project %q.", values.InstanceID, values.ProjectID)
			return nil
		}
		if err := services.Host.RemoveExternalIPs(ctx, values.ProjectID, values.InstanceZone, values.InstanceID); err != nil {
			return errors.Wrap(err, "failed to remove public ip")
		}
		services.Logger.Info("removed public IP address for instance %q, in zone %q in project %q.", values.InstanceID, values.InstanceZone, values.ProjectID)
		return nil
	})
}
