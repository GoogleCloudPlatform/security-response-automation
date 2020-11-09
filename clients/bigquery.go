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
)

// BigQuery client.
type BigQuery struct {
	client *bigquery.Client
}

// NewBigQuery returns the BigQuery client.
func NewBigQuery(ctx context.Context, projectID string) (*BigQuery, error) {
	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to init bigquery: %q", err)
	}
	return &BigQuery{client: client}, nil
}

// DatasetMetadata fetches the metadata for the dataset.
func (bq *BigQuery) DatasetMetadata(ctx context.Context, projectID, datasetID string) (*bigquery.DatasetMetadata, error) {
	return bq.client.DatasetInProject(projectID, datasetID).Metadata(ctx)
}

// OverwriteDatasetMetadata modifies specific Dataset metadata fields.
// This method ignores the existing metadata state (and possibly overwrites other updates) by doing a "blind write".
// See https://godoc.org/cloud.google.com/go/bigquery#Dataset.Update for details.
func (bq *BigQuery) OverwriteDatasetMetadata(ctx context.Context, projectID, datasetID string, dm bigquery.DatasetMetadataToUpdate) (*bigquery.DatasetMetadata, error) {
	blindWrite := ""
	return bq.client.DatasetInProject(projectID, datasetID).Update(ctx, dm, blindWrite)
}
