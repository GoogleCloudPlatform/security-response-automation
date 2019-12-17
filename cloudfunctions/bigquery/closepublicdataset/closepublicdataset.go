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

	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
)

// Values contains the required values needed for this function.
type Values struct {
	ProjectID string
	DatasetID string
	DryRun    bool
}

// Services contains the services needed for this function.
type Services struct {
	BigQuery *services.BigQuery
	Logger   *services.Logger
}

// Execute removes public access of a BigQuery dataset.
func Execute(ctx context.Context, values *Values, services *Services) error {
	if values.DryRun {
		services.Logger.Info("dry_run on, would have removed public access on bigquery dataset %q in project %q", values.DatasetID, values.ProjectID)
		return nil
	}
	if err := services.BigQuery.RemoveDatasetPublicAccess(ctx, values.ProjectID, values.DatasetID); err != nil {
		return errors.Wrapf(err, "error removing bigquery dataset %q public access in project %q", values.DatasetID, values.ProjectID)
	}
	services.Logger.Info("removed public access on bigquery dataset %q in project %q", values.DatasetID, values.ProjectID)
	return nil
}
