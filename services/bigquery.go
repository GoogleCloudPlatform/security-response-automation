package services

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

// BigQueryClient contains minimum interface required by the service.
type BigQueryClient interface {
	DatasetMetadata(ctx context.Context, projectID, datasetID string) (*bigquery.DatasetMetadata, error)
	OverwriteDatasetMetadata(ctx context.Context, projectID, datasetID string, dm bigquery.DatasetMetadataToUpdate) (*bigquery.DatasetMetadata, error)
}

// BigQuery service.
type BigQuery struct {
	client BigQueryClient
}

var publicUsers = map[string]bool{"allUsers": true, "allAuthenticatedUsers": true}

// NewBigQuery returns a BigQuery service.
func NewBigQuery(cs BigQueryClient) *BigQuery {
	return &BigQuery{client: cs}
}

// RemoveDatasetPublicAccess removes public users from a dataset.
func (bq *BigQuery) RemoveDatasetPublicAccess(ctx context.Context, projectID, datasetID string) error {
	md, err := bq.client.DatasetMetadata(ctx, projectID, datasetID)
	if err != nil {
		return errors.Wrapf(err, "failed to get metadata for bigquery dataset %q in project %q", datasetID, projectID)
	}
	dm := bigquery.DatasetMetadataToUpdate{
		Access: removePublicUsers(md),
	}
	if _, err := bq.client.OverwriteDatasetMetadata(ctx, projectID, datasetID, dm); err != nil {
		return errors.Wrapf(err, "failed to remove public access on bigquery dataset %q in project %q", datasetID, projectID)
	}
	return nil
}

func removePublicUsers(metadata *bigquery.DatasetMetadata) []*bigquery.AccessEntry {
	newAccesses := []*bigquery.AccessEntry{}
	for _, a := range metadata.Access {
		if !publicUsers[a.Entity] {
			newAccesses = append(newAccesses, a)
		}
	}
	return newAccesses
}
