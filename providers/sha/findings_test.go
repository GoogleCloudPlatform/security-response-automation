// Package sha contains methods used to read and deserialize SHA findings.
package sha

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
	"testing"

	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

const shaFinding = `{
  "notificationConfigName": "organizations/154584661726/notificationConfigs/sampleConfigId",
  "finding": {
    "name": "organizations/154584661726/sources/2673592633662526977/findings/3d71012c3b3951c62e61b105e002f12b",
    "parent": "organizations/154584661726/sources/2673592633662526977",
    "resourceName": "//cloudresourcemanager.googleapis.com/projects/997507777601",
    "state": "ACTIVE",
    "category": "ADMIN_SERVICE_ACCOUNT",
    "externalUri": "https://console.cloud.google.com/iam-admin/iam?project=aerial-jigsaw-235219",
    "sourceProperties": {
      "ReactivationCount": 0,
      "OffendingIamRoles": "{\"invalidRoles\":[{\"user\":\"serviceAccount:automation-service-account@aerial-jigsaw-235219.iam.gserviceaccount.com\",\"roles\":[\"roles/pubsub.admin\"]},{\"user\":\"serviceAccount:service-997507777601@containerregistry.iam.gserviceaccount.com\",\"roles\":[\"roles/owner\"]}]}",
      "ExceptionInstructions": "Add the security mark \"allow_admin_service_account\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
      "SeverityLevel": "Medium",
      "Recommendation": "Go to https://console.cloud.google.com/iam-admin/iam?project=aerial-jigsaw-235219 to review the policy. The following accounts have admin or owner roles: [serviceAccount:automation-service-account@aerial-jigsaw-235219.iam.gserviceaccount.com, serviceAccount:service-997507777601@containerregistry.iam.gserviceaccount.com]",
      "ProjectId": "aerial-jigsaw-235219",
      "AssetCreationTime": "2019-03-21t19:41:58.502z",
      "ScannerName": "IAM_SCANNER",
      "ScanRunId": "2019-09-25T19:50:20.831-07:00",
      "Explanation": "A service account has owner or admin privileges. It is recommended for privilege for privilege separation that no service accounts have Admin or Owner permissions."
    },
    "securityMarks": {
      "name": "organizations/154584661726/sources/2673592633662526977/findings/3d71012c3b3951c62e61b105e002f12b/securityMarks"
    },
    "eventTime": "2019-09-26T02:50:20.831Z",
    "createTime": "2019-09-23T18:50:37.131Z"
  }
}`

// TestForFailures attempts to unmarshal logs that are not valid.
func TestForShaFailures(t *testing.T) {
	const invalidFinding = `{"weird_fields": true}`
	test := []struct {
		name    string
		message *pubsub.Message
		exp     error
	}{
		{name: "invalid finding", message: &pubsub.Message{Data: []byte(invalidFinding)}, exp: entities.ErrUnmarshal},
		{name: "valid finding", message: &pubsub.Message{Data: []byte(shaFinding)}, exp: nil},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFinding(tt.message)
			if err == nil && tt.exp == nil {
				return
			}
			if err != nil && errors.Cause(err).Error() != tt.exp.Error() {
				t.Errorf("%s failed got:%q want:%q", tt.name, err, tt.exp)
			}
		})
	}
}

// TestForFailures attempts to unmarshal logs that are not valid.
func TestForShaIamScanner(t *testing.T) {
	const invalidFinding = `{"weird_fields": true}`
	test := []struct {
		name           string
		message        *pubsub.Message
		expScannerName string
		expProjectID   string
	}{
		{name: "valid finding", message: &pubsub.Message{Data: []byte(shaFinding)}, expScannerName: "IAM_SCANNER", expProjectID: "aerial-jigsaw-235219"},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := NewIamScanner(tt.message)
			if f.ScannerName() != tt.expScannerName {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ScannerName(), tt.expScannerName)
			}
			if f.ProjectID() != tt.expProjectID {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.ProjectID(), tt.expProjectID)
			}
		})
	}
}
