package entities

import (
	"testing"

	"cloud.google.com/go/pubsub"
)

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

func TestForShaFailures(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
		exp     error
	}{
		{
			"empty message",
			&pubsub.Message{},
			ErrShaUnmarshal,
		},
		{
			"does not have a resource name",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"sourceProperties": {
						"ScannerName": "IAM_SCANNER"
					}}}`)},
			ErrNoResourceName,
		},
		{
			"not a FIREWALL_SCANNER Finding",
			&pubsub.Message{Data: []byte(`{
				"finding": { 
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"sourceProperties": {
						"ScannerName": "IAM_SCANNER"
					}}}`)},
			ErrNotFirewall,
		},
		{
			"Unknown firewall category",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "CLOSE_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER"
					}}}`)},
			ErrUnknownRule,
		},
		{
			"does not have a project id",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER"
					}}}`)},
			ErrNoProjectID,
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			err := NewShaFinding().ReadShaFinding(tt.message)
			if err.Error() != tt.exp.Error() {
				t.Errorf("exp:%q got: %q", tt.exp, err)
			}
		})
	}
}
