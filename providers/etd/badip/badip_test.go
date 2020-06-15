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
			"finding": {
				"name": "organizations/0000000000000/sources/0000000000000000000/findings/6a30ce604c11417995b1fa260753f3b5",
				"parent": "organizations/0000000000000/sources/0000000000000000000",
				"resourceName": "//cloudresourcemanager.googleapis.com/projects/000000000000",
				"state": "ACTIVE",
				"category": "C2: Bad IP",
				"externalUri": "https://console.cloud.google.com/home?project=test-project-15511551515",
				"sourceProperties": {
					"detectionCategory": {
						"ruleName": "bad_ip"
					},
					"properties": {
						"instanceDetails": "/projects/test-project-15511551515/zones/us-central1-a/instances/bad-ip-caller",
							"network": {
								"project": "test-project-15511551515"
							}
					}
				},
				"securityMarks": {},
				"eventTime": "2019-11-22T18:34:36.153Z",
				"createTime": "2019-11-22T18:34:36.688Z"
			}
		}`
		badIPStackdriver = `{
			"jsonPayload": {
				"properties": {
					"instanceDetails": "/projects/test-project-15511551515/zones/us-central1-a/instances/bad-ip-caller",
					"network": {
						"project": "test-project-15511551515"
					}
				},
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	)

	for _, tt := range []struct {
		name      string
		ruleName  string
		finding   []byte
		projectID string
		instance  string
		zone      string
	}{
		{name: "bad_ip SD", finding: []byte(badIPStackdriver), ruleName: "bad_ip", projectID: "test-project-15511551515", instance: "bad-ip-caller", zone: "us-central1-a"},
		{name: "bad_ip CSCC", finding: []byte(badIPSCC), ruleName: "bad_ip", projectID: "test-project-15511551515", instance: "bad-ip-caller", zone: "us-central1-a"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, err := New(tt.finding)
			if err != nil {
				t.Fatalf("%q failed: %q", tt.name, err)
			}
			if name := f.Name(tt.finding); name != tt.ruleName {
				t.Errorf("%q got:%q want:%q", tt.name, name, tt.ruleName)
			}
			if err == nil && f != nil {
				values := f.CreateSnapshot()
				if values.ProjectID != tt.projectID {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
				}
				if values.Instance != tt.instance {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.Instance, tt.instance)
				}
				if values.Zone != tt.zone {
					t.Errorf("%s failed: got:%q want:%q", tt.name, values.Zone, tt.zone)
				}

			}
		})
	}
}
