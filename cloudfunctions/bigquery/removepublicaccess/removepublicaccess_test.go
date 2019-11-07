package removepublicaccess

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
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/services"
	"github.com/googlecloudplatform/threat-automation/services/helpers"
)

func TestReadFinding(t *testing.T) {
	const (
		publicDatasetFinding = `{
		  "notificationConfigName": "organizations/119612413569/notificationConfigs/active-findings",
		  "finding": {
			"name": "organizations/119612413569/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7",
			"parent": "organizations/119612413569/sources/7086426792249889955",
			"resourceName": "//bigquery.googleapis.com/projects/sha-resources-20191002/datasets/public_dataset",
			"state": "ACTIVE",
			"category": "PUBLIC_DATASET",
			"externalUri": "https://console.cloud.google.com/bigquery?project=sha-resources-20191002&folder&organizationId=119612413569&p=sha-resources-20191002&d=public_dataset&page=dataset",
			"sourceProperties": {
			  "ReactivationCount": 0,
			  "ExceptionInstructions": "Add the security mark \"allow_public_dataset\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
			  "SeverityLevel": "High",
			  "Recommendation": "Go to https://console.cloud.google.com/bigquery?project=sha-resources-20191002&folder&organizationId=119612413569&p=sha-resources-20191002&d=public_dataset&page=dataset, click \"SHARE DATASET\", search members for \"allUsers\" and \"allAuthenticatedUsers\",  and remove access for those members.",
			  "ProjectId": "sha-resources-20191002",
			  "AssetCreationTime": "2019-10-02T18:28:42.182Z",
			  "ScannerName": "DATASET_SCANNER",
			  "ScanRunId": "2019-10-03T11:40:22.538-07:00",
			  "Explanation": "This dataset is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
			},
			"securityMarks": {
			  "name": "organizations/119612413569/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7/securityMarks"
			},
			"eventTime": "2019-10-03T18:40:22.538Z",
			"createTime": "2019-10-03T18:40:23.445Z"
		  }
		}`
		wrongCategoryFinding = `{
		  "notificationConfigName": "organizations/119612413569/notificationConfigs/active-findings",
		  "finding": {
			"name": "organizations/119612413569/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7",
			"parent": "organizations/119612413569/sources/7086426792249889955",
			"resourceName": "//bigquery.googleapis.com/projects/sha-resources-20191002/datasets/public_dataset",
			"state": "ACTIVE",
			"category": "NOT_PUBLIC_DATASET",
			"externalUri": "https://console.cloud.google.com/bigquery?project=sha-resources-20191002&folder&organizationId=119612413569&p=sha-resources-20191002&d=public_dataset&page=dataset",
			"sourceProperties": {
			  "ReactivationCount": 0,
			  "ExceptionInstructions": "Add the security mark \"allow_public_dataset\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
			  "SeverityLevel": "High",
			  "Recommendation": "Go to https://console.cloud.google.com/bigquery?project=sha-resources-20191002&folder&organizationId=119612413569&p=sha-resources-20191002&d=public_dataset&page=dataset, click \"SHARE DATASET\", search members for \"allUsers\" and \"allAuthenticatedUsers\",  and remove access for those members.",
			  "ProjectId": "sha-resources-20191002",
			  "AssetCreationTime": "2019-10-02T18:28:42.182Z",
			  "ScannerName": "DATASET_SCANNER",
			  "ScanRunId": "2019-10-03T11:40:22.538-07:00",
			  "Explanation": "This dataset is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
			},
			"securityMarks": {
			  "name": "organizations/119612413569/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7/securityMarks"
			},
			"eventTime": "2019-10-03T18:40:22.538Z",
			"createTime": "2019-10-03T18:40:23.445Z"
		  }
		}`
	)
	for _, tt := range []struct {
		name          string
		projectID     string
		datasetID     string
		bytes         []byte
		expectedError error
	}{
		{name: "read", projectID: "sha-resources-20191002", datasetID: "public_dataset", bytes: []byte(publicDatasetFinding), expectedError: nil},
		{name: "wrong category", projectID: "", datasetID: "", bytes: []byte(wrongCategoryFinding), expectedError: services.ErrUnsupportedFinding},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
			}
			if err == nil && r.DatasetID != tt.datasetID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.DatasetID, tt.datasetID)
			}
		})
	}
}

func TestRemovePublicAccess(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name             string
		metadata         *bigquery.DatasetMetadata
		expectedMetadata *bigquery.DatasetMetadataToUpdate
		folderIDs        []string
		ancestry         *crm.GetAncestryResponse
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
			folderIDs: []string{"123"},
			ancestry:  helpers.CreateAncestors([]string{"folder/123"}),
		},
		{
			name:             "no valid folder",
			metadata:         &bigquery.DatasetMetadata{},
			expectedMetadata: nil,
			folderIDs:        []string{"456"},
			ancestry:         helpers.CreateAncestors([]string{"folder/123"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, bigqueryStub, crmStub := setup(tt.folderIDs)
			bigqueryStub.StubbedMetadata = tt.metadata
			bigqueryStub.SavedDatasetMetadata = tt.expectedMetadata
			crmStub.GetAncestryResponse = tt.ancestry
			values := &Values{
				ProjectID: "project-id",
				DatasetID: "dataset-id",
			}
			if err := Execute(ctx, values, &Services{
				Configuration: svcs.Configuration,
				BigQuery:      svcs.BigQuery,
				Resource:      svcs.Resource,
				Logger:        svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to remove public access in bigquery dataset:%q", tt.name, err)
			}

			if diff := cmp.Diff(tt.expectedMetadata, bigqueryStub.SavedDatasetMetadata, cmpopts.IgnoreUnexported(bigquery.DatasetMetadataToUpdate{})); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}

func setup(folderIDs []string) (*services.Global, *stubs.BigQueryStub, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := services.NewResource(crmStub, storageStub)
	bigqueryStub := &stubs.BigQueryStub{}
	bq := services.NewBigQuery(bigqueryStub)
	conf := &services.Configuration{
		RemovePublicAccess: &services.RemovePublicAccess{
			Resources: &services.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &services.Global{Logger: log, BigQuery: bq, Resource: res, Configuration: conf}, bigqueryStub, crmStub
}
