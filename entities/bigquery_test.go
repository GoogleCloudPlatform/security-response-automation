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
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
)

func TestRemoveDatasetPublicAccess(t *testing.T) {
	const (
		projectID = "test-project"
		datasetID = "test-dataset"
	)

	nonPublicAccessEntry := bigquery.AccessEntry{
		Entity: "user@org.com",
	}

	allUsersAccessEntry := bigquery.AccessEntry{
		Entity: "allUsers",
	}

	allAuthenticatedUsersAccessEntry := bigquery.AccessEntry{
		Entity: "allAuthenticatedUsers",
	}

	tests := []struct {
		name                   string
		datasetMetadata        *bigquery.DatasetMetadata
		updatedDatasetMetadata *bigquery.DatasetMetadata
		expectedError          error
	}{
		{
			name: "Remove BigQuery dataset public access",
			datasetMetadata: &bigquery.DatasetMetadata{
				Access: []*bigquery.AccessEntry{
					&nonPublicAccessEntry,
					&allUsersAccessEntry,
					&allAuthenticatedUsersAccessEntry,
				},
			},
			updatedDatasetMetadata: &bigquery.DatasetMetadata{
				Access: []*bigquery.AccessEntry{
					&nonPublicAccessEntry,
				},
			},
			expectedError: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bqStub := &stubs.BigQueryStub{
				StubbedMetadata:        tt.datasetMetadata,
				StubbedUpdatedMetadata: tt.updatedDatasetMetadata,
			}
			ctx := context.Background()
			bq := NewBigQuery(bqStub)

			newAccess, err := bq.RemoveDatasetPublicAccess(ctx, projectID, datasetID)

			if err != tt.expectedError {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}
			if diff := cmp.Diff(tt.updatedDatasetMetadata.Access, newAccess); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}
