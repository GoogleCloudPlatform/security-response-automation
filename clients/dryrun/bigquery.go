package dryrun

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
	"log"

	"cloud.google.com/go/bigquery"
	"github.com/googlecloudplatform/security-response-automation/clients"
)

// BigQuery client.
type BigQuery struct {
	client *clients.BigQuery
}

// NewDryRunBigQuery returns the BigQuery client.
func NewDryRunBigQuery(original *clients.BigQuery) (*BigQuery, error) {
	return &BigQuery{client: original}, nil
}

// DatasetMetadata fetches the metadata for the dataset.
func (bq *BigQuery) DatasetMetadata(ctx context.Context, projectID, datasetID string) (*bigquery.DatasetMetadata, error) {
	return bq.client.DatasetMetadata(ctx, projectID, datasetID)
}

// OverwriteDatasetMetadata modifies specific Dataset metadata fields.
// This method ignores the existing metadata state (and possibly overwrites other updates) by doing a "blind write".
// See https://godoc.org/cloud.google.com/go/bigquery#Dataset.Update for details.
func (bq *BigQuery) OverwriteDatasetMetadata(ctx context.Context, projectID, datasetID string, dm bigquery.DatasetMetadataToUpdate) (*bigquery.DatasetMetadata, error) {
	log.Printf("dry_run on, would call 'OverwriteDatasetMetadata' with params projectID: %q, datasetID: %q, DatasetMetadataToUpdate: %+v", projectID, datasetID, dm)
	return nil, nil
}
