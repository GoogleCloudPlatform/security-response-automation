package entities

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
	"github.com/pkg/errors"
)

// BigQueryClient contains minimum interface required by the entity.
type BigQueryClient interface {
	Init(ctx context.Context, projectID string) error
	OverwriteDatasetMetadata(ctx context.Context, projectID, datasetID string, dm bigquery.DatasetMetadataToUpdate) (*bigquery.DatasetMetadata, error)
}

// BigQuery entity.
type BigQuery struct {
	client BigQueryClient
}

// NewBigQuery returns a BigQuery entity.
func NewBigQuery(cs BigQueryClient) *BigQuery {
	return &BigQuery{client: cs}
}

// init initializes the bigquery client.
func (bq *BigQuery) init(ctx context.Context, projectID string) error {
	if err := bq.client.Init(ctx, projectID); err != nil {
		return errors.Wrap(errors.New("failed to init bigquery"), err.Error())
	}
	return nil
}

// RemoveDatasetPublicAccess removes allUsers and allAuthenticatedUsers access from a dataset metadata.
func (bq *BigQuery) RemoveDatasetPublicAccess(ctx context.Context, projectID, datasetID string) error {
	if err := bq.init(ctx, projectID); err != nil {
		return errors.Wrap(errors.New("failed to initialize bigquery"), err.Error())
	}
	// TODO implement & tests.
	fmt.Println("RemoveDatasetPublicAccess called. Project: ", projectID, "Dataset: ", datasetID)
	return nil
}
