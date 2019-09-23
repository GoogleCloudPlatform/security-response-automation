package entities

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

	"cloud.google.com/go/pubsub"
	"github.com/google/go-cmp/cmp"
)

// TestForFailures attempts to unmarshal logs that are not valid.
func TestForFailures(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		exp     error
	}{
		{
			"empty message",
			&pubsub.Message{},
			ErrUnmarshal,
		},
		{
			"not a stackdriver log",
			&pubsub.Message{Data: []byte(`{"insertId": "r7erfra3"}`)},
			ErrParsing,
		},
		{
			"not a finding",
			&pubsub.Message{Data: []byte(`{"logName": "projects/foo-123/logs/something-else"}`)},
			ErrParsing,
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewFinding().ReadFinding(tt.message); err.Error() != tt.exp.Error() {
				t.Errorf("exp:%q got: %q", tt.exp, err)
			}
		})
	}
}

// TestSuccess verifies reading a finding without an error.
func TestSuccess(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
	}{
		{
			"valid finding",
			&pubsub.Message{Data: []byte(`{"logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection"}`)},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewFinding().ReadFinding(tt.message); err != nil {
				t.Errorf("exp: nil got:%q", err)
			}
		})
	}
}

// TestReadProject verifies the proper parsing and return of the project from the affected resource.
func TestReadProject(t *testing.T) {
	test := []struct {
		name      string
		message   *pubsub.Message
		projectID string
	}{
		{
			"parse project",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                "affectedResources": [{
                                        "gcpResourceName":"//cloudresourcemanager.googleapis.com/projects/gke-test-inside"
                                        }],
					 "properties": {
						"project_id":  "test-project"
					}
                                }
                        }`)},
			"test-project",
		},
		{
			"no affected project",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                    "properties": {}
                                }
                        }`)},
			"",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFinding()
			if err := f.ReadFinding(tt.message); err != nil {
				t.Errorf("failed reading finding: %q", err)
			}
			proj := f.ProjectID()
			if proj != tt.projectID {
				t.Errorf("%s failed got:%q want:%q", tt.name, proj, tt.projectID)
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
			"project resource",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                "affectedResources": [{
                                        "gcpResourceName":"//cloudresourcemanager.googleapis.com/projects/gke-test-inside"
                                        }]
                                }
                        }`)},
			"projects/gke-test-inside",
		},
		{
			"folder resource",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                "affectedResources": [{
                                        "gcpResourceName":"//cloudresourcemanager.googleapis.com/folders/gke-test-inside"
                                        }]
                                }
                        }`)},
			"folders/gke-test-inside",
		},
		{
			"organization resource",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                "affectedResources": [{
                                        "gcpResourceName":"//cloudresourcemanager.googleapis.com/organizations/gke-test-inside"
                                        }]
                                }
                        }`)},
			"organizations/gke-test-inside",
		},
		{
			"multi-layer resource",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                "affectedResources": [{
                                        "gcpResourceName":"//cloudresourcemanager.googleapis.com/aaa/bbb/ccc/unknown/gke-test-inside"
                                        }]
                                }
                        }`)},
			"unknown/gke-test-inside",
		},
		{
			"not resource",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                "affectedResources": [{
                                        "gcpResourceName":"//cloudresourcemanager.googleapis.com"
                                        }]
                                }
                        }`)},
			"",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFinding()
			if err := f.ReadFinding(tt.message); err != nil {
				t.Errorf("failed reading finding: %q", err)
			}
			proj := f.Resource()
			if proj != tt.resource {
				t.Errorf("%s failed got:%q want:%q", tt.name, proj, tt.resource)
			}
		})
	}
}

// TestSubRule attempts to deserialize an finding with a known subrule.
func TestSubRule(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		exp     []string
	}{
		{
			"extract external member added as a project editor",
			genMessage("external_member_added_to_policy", `"externalMembers": ["user:external-member@gmail.com"]`),
			[]string{"user:external-member@gmail.com"},
		},
		{
			"extract external member added as a project owner",
			genMessage("external_member_invited_to_policy", `"externalMembers": ["user:external-member@gmail.com"]`),
			[]string{"user:external-member@gmail.com"},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFinding()
			if err := f.ReadFinding(tt.message); err != nil {
				t.Errorf("%s failed got:%q want:nil", tt.name, err)
				return
			}
			p := f.ext.JSONPayload.Properties.ExternalMembers
			if diff := cmp.Diff(p, tt.exp); diff != "" {
				t.Errorf("%s failed got:%q want:%q", tt.name, tt.exp, p)
			}
		})
	}
}

// TestExternalUsers attempts to list the external users.
func TestExternalUsers(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		exp     []string
	}{
		{
			"invalid log",
			&pubsub.Message{},
			[]string{},
		},
		{
			"no properties",
			genMessage("", ``),
			[]string{},
		},
		{
			"no external members",
			genMessage("external_member_added_to_policy", `"externalMembers": []`),
			[]string{},
		},
		{
			"one external user",
			genMessage("external_member_added_to_policy", `"externalMembers": ["user:hihijhoho@gmail.com"]`),
			[]string{"user:hihijhoho@gmail.com"},
		},
		{
			"two external users",
			genMessage("external_member_added_to_policy", `"externalMembers": ["user:hihijhoho@gmail.com", "user:test@test.com"]`),
			[]string{"user:hihijhoho@gmail.com", "user:test@test.com"},
		},
	}
	for _, tt := range test {
		f := NewFinding()
		t.Run(tt.name, func(t *testing.T) {
			f.ReadFinding(tt.message)
			eu := f.ExternalUsers()
			if diff := cmp.Diff(eu, tt.exp); diff != "" {
				t.Errorf("%s failed got:%q want:%q", tt.name, tt.exp, eu)
			}
		})
	}
}
func genMessage(subRule string, members string) *pubsub.Message {
	return &pubsub.Message{Data: []byte(fmt.Sprintf(`{
                "jsonPayload": {
                        "properties": {%s},
                        "detectionCategory": {
                                "subRuleName": "`+subRule+`"
                        }
                },
                "logName": "projects/dfoo-123/logs/threatdetection.googleapis.com`+"%%2F"+`detection"
                }`, members))}
}

func TestReadZone(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		zone    string
	}{
		{
			"bad ip parse zone",
			genBadNetworkMessage("us-central1-c", "bad_ip"),
			"us-central1-c",
		},
		{
			"bad domain parse zone",
			genBadNetworkMessage("us-central1-c", "bad_domain"),
			"us-central1-c",
		},
		{
			"not a bad network finding",
			genBadNetworkMessage("us-central1-c", ""),
			"",
		},
		{
			"no zone",
			genBadNetworkMessage("", "bad_ip"),
			"",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFinding()
			if err := f.ReadFinding(tt.message); err != nil {
				t.Errorf("failed reading finding: %q", err)
			}
			z := f.Zone()
			if z != tt.zone {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.zone)
			}
		})
	}
}

func genBadNetworkMessage(zone string, ruleName string) *pubsub.Message {
	return &pubsub.Message{Data: []byte(fmt.Sprintf(`{
		"jsonPayload": {
                        "properties": {
				"location":"` + zone + `"
			},
			"detectionCategory": {
				"ruleName": "` + ruleName + `"
			}
		},
		"logName": "projects/dfoo-123/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
	}`))}
}

func TestReadInstance(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		zone    string
	}{
		{
			"parse zone",
			&pubsub.Message{Data: []byte(`{
                                "logName": "projects/foo-123/logs/threatdetection.googleapis.com%2Fdetection",
                                "jsonPayload": {
                                    "affectedResources": [{
                                        "gcpResourceName":"//cloudresourcemanager.googleapis.com/projects/gke-test-inside"
                                    }],
				    "detectionCategory": {
					    "ruleName":"bad_ip"
				    },
                                    "properties":{
                                        "sourceInstance":"/projects/aerial-jigsaw-235219/zones/us-central1-c/instances/instance-2"
                                    }
                                }
                        }`)},
			"instance-2",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFinding()
			if err := f.ReadFinding(tt.message); err != nil {
				t.Errorf("failed reading finding: %q", err)
			}
			z := f.Instance()
			if z != tt.zone {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.zone)
			}
		})
	}
}
