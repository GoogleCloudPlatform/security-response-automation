package datasetscanner

import (
	"testing"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/bigquery/closepublicdataset"
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
			  "name": "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7/securityMarks"
			},
			"eventTime": "2019-10-03T18:40:22.538Z",
			"createTime": "2019-10-03T18:40:23.445Z"
		  }
		}`
		publicDatasetRemediated = `{
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
				"sra-remediated-event-time": "2019-10-03T18:40:22.538Z"
			  }
			},
			"eventTime": "2019-10-03T18:40:22.538Z",
			"createTime": "2019-10-03T18:40:23.445Z"
		  }
		}`
		errorMessage = "remediation ignored! Finding already processed and remediated. Security Mark: \"sra-remediated-event-time: 2019-10-03T18:40:22.538Z\""
	)
	extractedValues := &closepublicdataset.Values{
		ProjectID: "sha-resources-20191002",
		DatasetID: "public_dataset",
		Mark:      "2019-10-03T18:40:22.538Z",
		Name:      "organizations/154584661726/sources/7086426792249889955/findings/8682cf07ec50f921172082270bdd96e7",
	}
	for _, tt := range []struct {
		name           string
		ruleName       string
		values         *closepublicdataset.Values
		bytes          []byte
		expectedErrMsg string
	}{
		{name: "read", ruleName: "public_dataset", values: extractedValues, bytes: []byte(publicDatasetFinding), expectedErrMsg: ""},
		{name: "remediated", ruleName: "", values: nil, bytes: []byte(publicDatasetRemediated), expectedErrMsg: errorMessage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if err != nil && err.Error() != tt.expectedErrMsg {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedErrMsg)
			}
			if r != nil {
				if values := r.ClosePublicDataset(); *values != *tt.values {
					t.Errorf("%s failed: got:%v want:%v", tt.name, values, tt.values)
				}
				if name := r.Name(tt.bytes); name != tt.ruleName {
					t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
				}
			}
		})
	}
}
