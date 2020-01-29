package datasetscanner

import (
	"testing"

	"golang.org/x/xerrors"
)

func TestReadFinding(t *testing.T) {
	const (
		publicDatasetFinding = `{
		  "notificationConfigName": "organizations/154584661726/notificationConfigs/active-findings",
		  "finding": {
			"name": "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7",
			"parent": "organizations/154584661726/sources/7086426792249889955",
			"resourceName": "//bigquery.googleapis.com/projects/sha-resources-20191002/datasets/public_dataset",
			"state": "ACTIVE",
			"category": "PUBLIC_DATASET",
			"externalUri": "https://console.cloud.google.com/bigquery?project=sha-resources-20191002&folder&organizationId=154584661726&p=sha-resources-20191002&d=public_dataset&page=dataset",
			"sourceProperties": {
			  "ReactivationCount": 0,
			  "ExceptionInstructions": "Add the security mark \"allow_public_dataset\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
			  "SeverityLevel": "High",
			  "Recommendation": "Go to https://console.cloud.google.com/bigquery?project=sha-resources-20191002&folder&organizationId=154584661726&p=sha-resources-20191002&d=public_dataset&page=dataset, click \"SHARE DATASET\", search members for \"allUsers\" and \"allAuthenticatedUsers\",  and remove access for those members.",
			  "ProjectId": "sha-resources-20191002",
			  "AssetCreationTime": "2019-10-02T18:28:42.182Z",
			  "ScannerName": "DATASET_SCANNER",
			  "ScanRunId": "2019-10-03T11:40:22.538-07:00",
			  "Explanation": "This dataset is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
			},
			"securityMarks": {
			  "name": "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7/securityMarks",
			  "marks": {
				"sratest1": "true",
				"sraRemediated": "12dcb68e4b5b4e26cb66799cdbb5ae2d92b830428a50e13d1a282fa29a941caf",
				"sratest2": "true"
			  }
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
		hash          string
		findingName   string
		bytes         []byte
		expectedError error
	}{
		{name: "read", projectID: "sha-resources-20191002", datasetID: "public_dataset",
			hash:        "12dcb68e4b5b4e26cb66799cdbb5ae2d92b830428a50e13d1a282fa29a941caf",
			findingName: "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7",
			bytes:       []byte(publicDatasetFinding), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			values := f.ClosePublicDataset()
			if err == nil && values != nil && values.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
			}
			if err == nil && values != nil && values.DatasetID != tt.datasetID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.DatasetID, tt.datasetID)
			}
			if err == nil && values != nil && values.Hash != tt.hash {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.Hash, tt.hash)
			}
			if err == nil && values != nil && values.Name != tt.findingName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.Name, tt.findingName)
			}
		})
	}
}
