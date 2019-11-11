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
	"testing"

	"cloud.google.com/go/bigquery"
	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
)

func TestRemoveDatasetPublicAccess(t *testing.T) {
	const (
		projectID = "test-project"
		datasetID = "test-dataset"
	)
	tests := []struct {
		name          string
		fakedMetadata *bigquery.DatasetMetadata
		expected      []*bigquery.AccessEntry
	}{
		{
			name: "remove bigquery dataset public access",
			fakedMetadata: &bigquery.DatasetMetadata{
				Access: []*bigquery.AccessEntry{
					{Entity: "user@org.com"},
					{Entity: "allUsers"},
					{Entity: "allAuthenticatedUsers"},
					{Entity: "anotheruser@org.com"},
				},
			},
			expected: []*bigquery.AccessEntry{
				{Entity: "user@org.com"},
				{Entity: "anotheruser@org.com"},
			},
		},
		{
			name: "remove all public access",
			fakedMetadata: &bigquery.DatasetMetadata{
				Access: []*bigquery.AccessEntry{
					{Entity: "allUsers"},
					{Entity: "allAuthenticatedUsers"},
				},
			},
			expected: []*bigquery.AccessEntry{},
		},
		{
			name: "no public access",
			fakedMetadata: &bigquery.DatasetMetadata{
				Access: []*bigquery.AccessEntry{
					{Entity: "foo@foo.com"},
				},
			},
			expected: []*bigquery.AccessEntry{
				{Entity: "foo@foo.com"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bqStub := &stubs.BigQueryStub{StubbedMetadata: tt.fakedMetadata}
			ctx := context.Background()
			bq := NewBigQuery(bqStub)
			if err := bq.RemoveDatasetPublicAccess(ctx, projectID, datasetID); err != nil {
				t.Errorf("%v failed:%q", tt.name, err)
			}
			if diff := cmp.Diff(bqStub.SavedDatasetMetadata.Access, tt.expected); diff != "" {
				t.Errorf("%v failed:%+v", tt.name, diff)
			}
		})
	}
}
