/*
Package entities contains abstractions around common objects.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package entities

import (
	"testing"

	"github.com/GoogleCloudPlatform/threat-automation/clients"
	cs "google.golang.org/api/compute/v1"
)

const (
	projectID = "test-project-id"
	ruleName  = "generic-rule-name"
)

func TestEnableFirewallRule(t *testing.T) {
	tests := []struct {
		name             string
		expectedError    error
		expectedResponse *cs.Firewall
	}{
		{
			name:             "enable rule",
			expectedError:    nil,
			expectedResponse: &cs.Firewall{Disabled: false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &clients.MockClients{}
			f := NewFirewall(mock)
			_, err := f.EnableFirewallRule(projectID, ruleName)
			if err != tt.expectedError {
				t.Errorf("%v failed exp:%v got: %v", tt.name, tt.expectedError, err)
			}
			if mock.SavedFirewallRule.Disabled != tt.expectedResponse.Disabled {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, mock.SavedFirewallRule)
			}

		})
	}
}

func TestDisableFirewallRule(t *testing.T) {
	tests := []struct {
		name             string
		expectedError    error
		expectedResponse *cs.Firewall
	}{
		{
			name:             "disable rule",
			expectedError:    nil,
			expectedResponse: &cs.Firewall{Disabled: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &clients.MockClients{}
			f := NewFirewall(mock)
			_, err := f.DisableFirewallRule(projectID, ruleName)
			if err != tt.expectedError {
				t.Errorf("%v failed exp:%q got: %q", tt.name, tt.expectedError, err)
			}
			if mock.SavedFirewallRule.Disabled != tt.expectedResponse.Disabled {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, mock.SavedFirewallRule)
			}

		})
	}
}
