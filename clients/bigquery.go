package clients

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
	"fmt"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/option"
)

// BigQuery client.
type BigQuery struct {
	service *bigquery.Client
}

// NewBigQuery returns and initializes the BigQuery client.
func NewBigQuery(ctx context.Context, projectID string, authFile string) (*BigQuery, error) {
	c, err := bigquery.NewClient(ctx, projectID, option.WithCredentialsFile(authFile))
	if err != nil {
		return nil, fmt.Errorf("failed to init bigquery: %q", err)
	}

	return &BigQuery{service: c}, nil
}

// GetDatasetMetadata fetches the metadata for the dataset.
func (bq *BigQuery) GetDatasetMetadata(ctx context.Context, projectID, datasetID string) (*bigquery.DatasetMetadata, error) {
	return bq.service.DatasetInProject(projectID, datasetID).Metadata(ctx)
}

// Update modifies specific Dataset metadata fields.
func (bq *BigQuery) UpdateDatasetMetadata(ctx context.Context, projectID, datasetID string, dm bigquery.DatasetMetadataToUpdate) (*bigquery.DatasetMetadata, error) {
	return bq.service.DatasetInProject(projectID, datasetID).Update(ctx, dm, "")
}
