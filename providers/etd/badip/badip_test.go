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
			  "securityMarks": {},
			  "eventTime": "2019-11-22T18:34:36.153Z",
			  "createTime": "2019-11-22T18:34:36.688Z"
			}
	  }`
		badIPStackdriver = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project",
					"instanceDetails": "/zones/zone-name/instances/source-instance-name"
				},
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	)

	for _, tt := range []struct {
		name     string
		ruleName string
		mapTo    []byte
		finding  []byte
	}{
		{name: "bad_ip SD", finding: []byte(badIPStackdriver), ruleName: "bad_ip"},
		{name: "bad_ip CSCC", finding: []byte(badIPSCC), ruleName: "bad_ip"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.finding)
			if err != nil {
				t.Fatalf("%q failed: %q", tt.name, err)
			}
			if name := f.Name(tt.finding); name != tt.ruleName {
				t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
			}
		})
	}
}
