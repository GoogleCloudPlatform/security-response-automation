package closepublicdataset

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
	ProjectID, DatasetID string
}

// Services contains the services needed for this function.
type Services struct {
	Configuration *services.Configuration
	BigQuery      *services.BigQuery
	Resource      *services.Resource
	Logger        *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.DatasetScanner
	v := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	switch finding.GetFinding().GetCategory() {
	case "PUBLIC_DATASET":
		if sha.IgnoreFinding(finding.GetFinding()) {
			return nil, services.ErrUnsupportedFinding
		}
		v.ProjectID = finding.GetFinding().GetSourceProperties().GetProjectID()
		v.DatasetID = sha.Dataset(finding.GetFinding().GetResourceName())
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if v.ProjectID == "" || v.DatasetID == "" {
		return nil, services.ErrValueNotFound
	}
	return v, nil
}

// Execute removes public access of a BigQuery dataset.
func Execute(ctx context.Context, values *Values, services *Services) error {
	resources := services.Configuration.ClosePublicDataset.Resources
	return services.Resource.IfProjectWithinResources(ctx, resources, values.ProjectID, func() error {
		if err := services.BigQuery.RemoveDatasetPublicAccess(ctx, values.ProjectID, values.DatasetID); err != nil {
			return errors.Wrapf(err, "error removing bigquery dataset %q public access in project %q", values.DatasetID, values.ProjectID)
		}
		services.Logger.Info("removed public access on bigquery dataset %q in project %q", values.DatasetID, values.ProjectID)
		return nil
	})
}
