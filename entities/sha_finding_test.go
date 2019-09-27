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

func TestShaSuccess(t *testing.T) {
	test := []struct {
		name    string
		message *pubsub.Message
	}{
		{
			"valid finding",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			if err := NewShaFinding().ReadShaFinding(tt.message); err != nil {
				t.Errorf("exp: nil got:%q", err)
			}
		})
	}
}

func TestShaReadProjectID(t *testing.T) {
	test := []struct {
		name      string
		message   *pubsub.Message
		projectID string
	}{
		{
			"Read ProjectID successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"teste-project",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewShaFinding()
			if err := f.ReadShaFinding(tt.message); err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.ProjectID()
			if z != tt.projectID {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.projectID)
			}
		})
	}
}

func TestShaReadResourceName(t *testing.T) {
	test := []struct {
		name         string
		message      *pubsub.Message
		resourceName string
	}{
		{
			"Read ResourceName successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewShaFinding()
			if err := f.ReadShaFinding(tt.message); err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.ResourceName()
			if z != tt.resourceName {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.resourceName)
			}
		})
	}
}

func TestShaReadCategory(t *testing.T) {
	test := []struct {
		name     string
		message  *pubsub.Message
		category string
	}{
		{
			"Read Category successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"OPEN_FIREWALL",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewShaFinding()
			if err := f.ReadShaFinding(tt.message); err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.Category()
			if z != tt.category {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.category)
			}
		})
	}
}

func TestShaReadScannerName(t *testing.T) {
	test := []struct {
		name        string
		message     *pubsub.Message
		scannerName string
	}{
		{
			"Read Category successfully",
			&pubsub.Message{Data: []byte(`{
				"finding": {
					"resourceName": "//compute.googleapis.com/projects/teste-project/global/firewalls/6190685430815455733",
					"category": "OPEN_FIREWALL",
					"sourceProperties": {
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
					}}}`)},
			"FIREWALL_SCANNER",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f := NewShaFinding()
			if err := f.ReadShaFinding(tt.message); err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.ScannerName()
			if z != tt.scannerName {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.scannerName)
			}
		})
	}
}
