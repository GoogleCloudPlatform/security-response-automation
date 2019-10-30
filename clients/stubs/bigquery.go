package stubs

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

	"cloud.google.com/go/bigquery"
)

// BigQueryStub provides a stub for the BigQuery client.
type BigQueryStub struct {
	StubbedGetMetadata    *bigquery.DatasetMetadata
	SubbedMetadataUpdated *bigquery.DatasetMetadata
}

// GetDatasetMetadata fetches the metadata for the dataset.
func (s *BigQueryStub) GetDatasetMetadata(ctx context.Context, projectID, datasetID string) (*bigquery.DatasetMetadata, error) {
	return s.StubbedGetMetadata, nil
}

// Update modifies specific Dataset metadata fields.
func (s *BigQueryStub) UpdateDatasetMetadata(ctx context.Context, projectID, datasetID string, dm bigquery.DatasetMetadataToUpdate) (*bigquery.DatasetMetadata, error) {
	return s.SubbedMetadataUpdated, nil
}
