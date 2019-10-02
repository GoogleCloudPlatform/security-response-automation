package sha

import (
	"testing"

	"cloud.google.com/go/pubsub"
	"github.com/pkg/errors"
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
			errors.New("unexpected end of JSON input: failed to unmarshal"),
		},
		{
			"missing Source properties body",
			&pubsub.Message{Data: []byte(`{
				"finding": { "sourceProperties":}}`)},
			errors.New("invalid character '}' looking for beginning of value: failed to unmarshal"),
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
					"category": "CLOSE_FIREWALL",
					"sourceProperties": {
						"ScannerName": "IAM_SCANNER",
						"ProjectId": "teste-project" 
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
						"ScannerName": "FIREWALL_SCANNER",
						"ProjectId": "teste-project"
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
			_, err := NewFirewallScanner(tt.message)
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
				"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
				"finding": {
				  "name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e", 
				  "parent": "organizations/1055058813388/sources/1986930501971458034",  
				  "resourceName": "//compute.googleapis.com/projects/onboarding-pedro/global/firewalls/6190685430815455733",
				  "state": "ACTIVE", 
				  "category": "OPEN_FIREWALL",
				  "externalUri": "https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-pedro",  
				  "sourceProperties": { 
					"ReactivationCount": 0.0,
					"Allowed": "[{\"IPProtocol\":\"tcp\",\"ipProtocol\":\"tcp\",\"port\":[\"80\"],\"ports\":[\"80\"]}]", 
					"ExceptionInstructions": "Add the security mark \"allow_open_firewall\" to the asset with a value of \"true\" to prevent this finding from being activated again.", 
					"SeverityLevel": "High",
					"Recommendation": "Restrict the firewall rules at: https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-pedro", 
					"AllowedIpRange": "All",
					"ActivationTrigger": "Allows all IP addresses",
					"ProjectId": "onboarding-pedro",
					"DeactivationReason": "The asset was deleted.",
					"SourceRange": "[\"0.0.0.0/0\"]",  
					"AssetCreationTime": "2019-08-21t06:28:58.140-07:00",
					"ScannerName": "FIREWALL_SCANNER", 
					"ScanRunId": "2019-09-17T07:10:21.961-07:00",  
					"Explanation": "Firewall rules that allow connections from all IP addresses or on all ports may expose resources to attackers." 
				  },  
				  "securityMarks": { 
					"name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e/securityMarks" 
				  },  
				  "eventTime": "2019-09-19T16:58:39.276Z",
				  "createTime": "2019-09-16T22:11:59.977Z"
				}  
			  }`)},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewFirewallScanner(tt.message); err != nil {
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
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
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
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
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
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
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
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.ScannerName()
			if z != tt.scannerName {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.scannerName)
			}
		})
	}
}

func TestShaReadFirewallID(t *testing.T) {
	test := []struct {
		name       string
		message    *pubsub.Message
		firewallID string
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
			"6190685430815455733",
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewFirewallScanner(tt.message)
			if err != nil {
				t.Errorf("failed reading SHA finding: %q", err)
			}
			z := f.FirewallID()
			if z != tt.firewallID {
				t.Errorf("%s failed got:%q want:%q", tt.name, z, tt.firewallID)
			}
		})
	}
}
