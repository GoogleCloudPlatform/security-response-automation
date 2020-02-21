package badip

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

	"github.com/google/go-cmp/cmp"

	"github.com/googlecloudplatform/security-response-automation/cloudfunctions/gce/createsnapshot"
)

func TestBadIP(t *testing.T) {
	const (
		badIPSCC = `{
			"notificationConfigName": "organizations/0000000000000/notificationConfigs/noticonf-active-001-id",
			"finding": {
			  "name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5",
			  "parent": "organizations/0000000000000/sources/0000000000000000000",
			  "resourceName": "//cloudresourcemanager.googleapis.com/projects/000000000000",
			  "state": "ACTIVE",
			  "category": "C2: Bad IP",
			  "externalUri": "https://console.cloud.google.com/home?project=test-project-15511551515",
			  "sourceProperties": {
					"detectionCategory_ruleName": "bad_ip",
				  "properties_project_id": "test-project-15511551515",
				  "properties_instanceDetails": "/projects/test-project-15511551515/zones/us-central1-a/instances/bad-ip-caller",
				  "properties_location": "us-central1-a"
			  },
			  "securityMarks": {
				"name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5/securityMarks",
				"marks": {
					"sra-remediated-event-time": "2019-11-22T18:34:00.000Z"
				}
			  },
			  "eventTime": "2019-11-22T18:34:36.153Z",
			  "createTime": "2019-11-22T18:34:36.688Z"
			}
	  }`
		badIPStackdriver = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project-15511551515",
					"instanceDetails": "/zones/us-central1-a/instances/bad-ip-caller"
				},
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	)
	sdExpectedValues := &createsnapshot.Values{
		ProjectID: "test-project-15511551515",
		RuleName:  "bad_ip",
		Instance:  "bad-ip-caller",
		Zone:      "us-central1-a",
	}
	sccExpectedValues := &createsnapshot.Values{
		ProjectID: "test-project-15511551515",
		RuleName:  "bad_ip",
		Instance:  "bad-ip-caller",
		Zone:      "us-central1-a",
		Mark:      "2019-11-22T18:34:36.153Z",
		Name:      "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5",
	}
	for _, tt := range []struct {
		name           string
		values         *createsnapshot.Values
		ruleName       string
		finding        []byte
		expectedErrMsg string
	}{
		{name: "bad_ip SD", values: sdExpectedValues, finding: []byte(badIPStackdriver), ruleName: "bad_ip", expectedErrMsg: ""},
		{name: "bad_ip CSCC", values: sccExpectedValues, finding: []byte(badIPSCC), ruleName: "bad_ip", expectedErrMsg: ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.finding)
			if err != nil && tt.expectedErrMsg != "" && err.Error() != tt.expectedErrMsg {
				t.Fatalf("%s failed: got:%q want:%q", tt.name, err, tt.expectedErrMsg)
			}
			if f != nil {
				values := f.CreateSnapshot()
				if diff := cmp.Diff(values, tt.values); diff != "" {
					t.Errorf("%q failed, difference:%+v", tt.name, diff)
				}
				if name := f.Name(tt.finding); name != tt.ruleName {
					t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
				}
			}
		})
	}
}
