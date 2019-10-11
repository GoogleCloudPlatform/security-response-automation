// Package etd contains methods used to read and deserialize ETD findings.
package etd

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
	"fmt"
	"testing"

	"github.com/googlecloudplatform/threat-automation/entities"
	"golang.org/x/xerrors"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
)

// TestForFailures attempts to unmarshal logs that are not valid.
func TestForFailures(t *testing.T) {
	noLogName := &pubsub.Message{Data: []byte(`{"insertId": "r7erfra3"}`)}
	noFinding := &pubsub.Message{Data: []byte(`{"logName": "projects/foo-123/logs/something-else"}`)}
	test := []struct {
		name    string
		message *pubsub.Message
		exp     error
	}{
		{name: "empty message", message: &pubsub.Message{}, exp: entities.ErrUnmarshal},
		{name: "no long name", message: noLogName, exp: entities.ErrParsing},
		{name: "no finding", message: noFinding, exp: entities.ErrParsing},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewBadIP(tt.message)
			if !xerrors.Is(errors.Cause(err), tt.exp) {
				t.Errorf("%s failed got:%q want:%q", tt.name, err, tt.exp)
			}
		})
	}
}

// TestReadResource verifies the proper parsing and return of the resource from the affected project.
func TestReadResource(t *testing.T) {
	test := []struct {
		name     string
		message  *pubsub.Message
		resource string
	}{
		{
			name: "project resource",
			message: &pubsub.Message{Data: []byte(`{
				"logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
				"jsonPayload": {
					"affectedResources": [{
						"gcpResourceName":"//cloudresourcemanager.googleapis.com/projects/gke-test-inside"
					}]
				}
			}`)},
			resource: "projects/gke-test-inside",
		},
		{
			name: "folder resource",
			message: &pubsub.Message{Data: []byte(`{
				"logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
        "jsonPayload": {
        	"affectedResources": [{
          	"gcpResourceName":"//cloudresourcemanager.googleapis.com/folders/gke-test-inside"
					}]
				}
      }`)},
			resource: "folders/gke-test-inside",
		},
		{
			name: "organization resource",
			message: &pubsub.Message{Data: []byte(`{
				"logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
        "jsonPayload": {
        	"affectedResources": [{
          	"gcpResourceName":"//cloudresourcemanager.googleapis.com/organizations/gke-test-inside"
					}]
				}
      }`)},
			resource: "organizations/gke-test-inside",
		},
		{
			name: "multi-layer resource",
			message: &pubsub.Message{Data: []byte(`{
				"logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
        "jsonPayload": {
        	"affectedResources": [{
          	"gcpResourceName":"//cloudresourcemanager.googleapis.com/aaa/bbb/ccc/unknown/gke-test-inside"
					}]
				}
      }`)},
			resource: "unknown/gke-test-inside",
		},
		{
			name: "not resource",
			message: &pubsub.Message{Data: []byte(`{
				"logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
        "jsonPayload": {
        	"affectedResources": [{
          	"gcpResourceName":"//cloudresourcemanager.googleapis.com"
					}]
				}
      }`)},
			resource: "",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			fg, err := NewExternalMembersFinding(tt.message)
			if err != nil {
				t.Errorf("%s failed reading finding: %q", tt.name, err)
			}
			a := fg.AffectedResource()
			if a != tt.resource {
				t.Errorf("%s failed got:%q want:%q", tt.name, a, tt.resource)
			}
		})
	}
}

// TestReadZone reads zone from BadIP.
func TestReadZone(t *testing.T) {
	test := []struct {
		name      string
		message   *pubsub.Message
		zone      string
		expected  error
		projectID string
	}{
		{name: "bad ip parse zone", message: genBadNetworkMessage("us-central1-c", "bad_ip"), zone: "us-central1-c", expected: nil, projectID: "test-project"},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewBadIP(tt.message)
			if err != nil {
				t.Errorf("%s failed reading finding: %q", tt.name, err)
			}
			if f.RuleName() != "bad_ip" {
				t.Errorf("%s failed with wrong name: got:%q want:bad_ip", tt.name, f.RuleName())
			}
			if f.Zone() != tt.zone {
				t.Errorf("%s failed got:%q want:%q", tt.name, f.Zone(), tt.zone)
			}
			if f.ProjectID() != tt.projectID {
				t.Errorf("%s failed reading project ID: got:%q want:%q", tt.name, f.ProjectID(), tt.projectID)
			}
		})
	}
}

func genBadNetworkMessage(zone string, ruleName string) *pubsub.Message {
	return &pubsub.Message{Data: []byte(fmt.Sprintf(`{
		"jsonPayload": {
			"properties": {
				"location":"` + zone + `",
				"project_id": "test-project"
			},
			"detectionCategory": {
				"ruleName": "` + ruleName + `"
			}
		},
		"logName": "projects/dfoo-123/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
	}`))}
}
