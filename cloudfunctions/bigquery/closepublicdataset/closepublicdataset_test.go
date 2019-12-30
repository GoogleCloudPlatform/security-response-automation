package closepublicdataset

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
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
)

func TestClosePublicDataset(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name             string
		metadata         *bigquery.DatasetMetadata
		expectedMetadata *bigquery.DatasetMetadataToUpdate
	}{
		{
			name: "remove bigquery dataset public access",
			metadata: &bigquery.DatasetMetadata{
				Access: []*bigquery.AccessEntry{
					{Entity: "user@org.com"},
					{Entity: "allUsers"},
					{Entity: "allAuthenticatedUsers"},
					{Entity: "anotheruser@org.com"},
				},
			},
			expectedMetadata: &bigquery.DatasetMetadataToUpdate{
				Access: []*bigquery.AccessEntry{
					{Entity: "user@org.com"},
					{Entity: "anotheruser@org.com"},
				},
			},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, bigqueryStub := setup()
			bigqueryStub.StubbedMetadata = tt.metadata
			bigqueryStub.SavedDatasetMetadata = tt.expectedMetadata
			values := &Values{
				ProjectID: "project-id",
				DatasetID: "dataset-id",
			}
			bq := services.NewBigQuery(bigqueryStub)
			if err := Execute(ctx, values, &Services{
				BigQuery: bq,
				Logger:   svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to remove public access in bigquery dataset:%q", tt.name, err)
			}

			if diff := cmp.Diff(tt.expectedMetadata, bigqueryStub.SavedDatasetMetadata, cmpopts.IgnoreUnexported(bigquery.DatasetMetadataToUpdate{})); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}

func setup() (*services.Global, *stubs.BigQueryStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	bigqueryStub := &stubs.BigQueryStub{}
	return &services.Global{Logger: log}, bigqueryStub
}
