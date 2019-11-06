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

	"cloud.google.com/go/bigquery"
	"github.com/pkg/errors"
)

// BigQueryClient contains minimum interface required by the entity.
type BigQueryClient interface {
	Init(ctx context.Context, projectID string) error
	DatasetMetadata(ctx context.Context, projectID, datasetID string) (*bigquery.DatasetMetadata, error)
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

// Init initializes the BigQuery client.
func (bq *BigQuery) Init(ctx context.Context, projectID string) error {
	return bq.client.Init(ctx, projectID)
}

// RemoveDatasetPublicAccess removes allUsers and allAuthenticatedUsers access from a dataset metadata.
func (bq *BigQuery) RemoveDatasetPublicAccess(ctx context.Context, projectID, datasetID string) ([]*bigquery.AccessEntry, error) {
	md, err := bq.client.DatasetMetadata(ctx, projectID, datasetID)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get metadata for bigquery dataset %q in project %q", datasetID, projectID)
	}
	dm := bigquery.DatasetMetadataToUpdate{
		Access: nonPublicAccess(md),
	}
	updatedMetadata, err := bq.client.OverwriteDatasetMetadata(ctx, projectID, datasetID, dm)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to remove public access on bigquery dataset %q in project %q", datasetID, projectID)
	}
	return updatedMetadata.Access, nil
}

func nonPublicAccess(metadata *bigquery.DatasetMetadata) []*bigquery.AccessEntry {
	newAccesses := []*bigquery.AccessEntry{}
	for _, a := range metadata.Access {
		if "allUsers" != a.Entity && "allAuthenticatedUsers" != a.Entity {
			newAccesses = append(newAccesses, a)
		}
	}
	return newAccesses
}
