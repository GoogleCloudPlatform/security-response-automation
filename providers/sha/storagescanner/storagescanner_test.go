package storagescanner

import (
	"testing"

	"golang.org/x/xerrors"
)

func TestReadFindingEnableBucketOnlyPolicy(t *testing.T) {
	const (
		storageScanner = `{
			"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
			"finding": {
				"name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
				"parent": "organizations/154584661726/sources/2673592633662526977",
				"resourceName": "//storage.googleapis.com/this-is-public-on-purpose",
				"state": "ACTIVE",
				"category": "BUCKET_POLICY_ONLY_DISABLED",
				"externalUri": "https://console.cloud.google.com/storage/browser/this-is-public-on-purpose",
				"sourceProperties": {
					"ReactivationCount": 0.0,
					"ExceptionInstructions": "Add the security mark \"allow_public_bucket_acl\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Go to https://console.cloud.google.com/storage/browser/this-is-public-on-purpose, click on the Permissions tab, and remove \"allUsers\" and \"allAuthenticatedUsers\" from the bucket's members.",
					"ProjectId": "aerial-jigsaw-235219",
					"AssetCreationTime": "2019-09-19T20:08:29.102Z",
					"ScannerName": "STORAGE_SCANNER",
					"ScanRunId": "2019-09-23T10:20:27.204-07:00",
					"Explanation": "This bucket is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
				},
				"securityMarks": {
					"name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8/securityMarks",
					"marks": {
						"babab": "3"
					}
				},
				"eventTime": "2019-09-23T17:20:27.204Z",
				"createTime": "2019-09-23T17:20:27.934Z"
			}
		}`
	)
	for _, tt := range []struct {
		name, bucket, projectID string
		bytes                   []byte
		expectedError           error
	}{
		{name: "read", bucket: "this-is-public-on-purpose", projectID: "aerial-jigsaw-235219", bytes: []byte(storageScanner), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			values := r.EnableBucketOnlyPolicy()
			if r != nil && err == nil && values.BucketName != tt.bucket {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.BucketName, tt.bucket)
			}
			if r != nil && err == nil && values.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
			}
		})
	}
}

func TestReadFindingCloseBucket(t *testing.T) {
	const (
		storageScanner = `{
			"notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
			"finding": {
				"name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8",
				"parent": "organizations/154584661726/sources/2673592633662526977",
				"resourceName": "//storage.googleapis.com/this-is-public-on-purpose",
				"state": "ACTIVE",
				"category": "PUBLIC_BUCKET_ACL",
				"externalUri": "https://console.cloud.google.com/storage/browser/this-is-public-on-purpose",
				"sourceProperties": {
					"ReactivationCount": 0.0,
					"ExceptionInstructions": "Add the security mark \"allow_public_bucket_acl\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Go to https://console.cloud.google.com/storage/browser/this-is-public-on-purpose, click on the Permissions tab, and remove \"allUsers\" and \"allAuthenticatedUsers\" from the bucket's members.",
					"ProjectId": "aerial-jigsaw-235219",
					"AssetCreationTime": "2019-09-19T20:08:29.102Z",
					"ScannerName": "STORAGE_SCANNER",
					"ScanRunId": "2019-09-23T10:20:27.204-07:00",
					"Explanation": "This bucket is public and can be accessed by anyone on the Internet. \"allUsers\" represents anyone on the Internet, and \"allAuthenticatedUsers\" represents anyone who is authenticated with a Google account; neither is constrained to users within your organization."
				},
				"securityMarks": {
					"name": "organizations/154584661726/sources/2673592633662526977/findings/782e52631d61da6117a3772137c270d8/securityMarks",
					"marks": {
						"babab": "3"
					}
				},
				"eventTime": "2019-09-23T17:20:27.204Z",
				"createTime": "2019-09-23T17:20:27.934Z"
			}
		}`
	)
	for _, tt := range []struct {
		name, bucket, projectID string
		bytes                   []byte
		expectedError           error
	}{
		{name: "read", bucket: "this-is-public-on-purpose", projectID: "aerial-jigsaw-235219", bytes: []byte(storageScanner), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r != nil {
				values := r.CloseBucket()
				if values.BucketName != tt.bucket {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.BucketName, tt.bucket)
				}
				if values.ProjectID != tt.projectID {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
				}
			}

		})
	}
}
