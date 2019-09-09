/*
Package host contains methods to change host resources.

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
package host

import (
	"testing"

	"github.com/GoogleCloudPlatform/threat-automation/automation/clients"

	cs "google.golang.org/api/compute/v1"
)

const (
	projectID = "test-project-id"
	zone      = "test-zone"
	disk      = "test-disk"
	snapshot  = "test-snapshot"
)

func TestCreateDiskSnapshot(t *testing.T) {
	tests := []struct {
		name             string
		expectedError    error
		expectedResponse *cs.Snapshot
	}{
		{
			name:             "test",
			expectedError:    nil,
			expectedResponse: &cs.Snapshot{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := clients.NewMockClients()
			s := NewHost(mock)
			if _, err := s.CreateDiskSnapshot(projectID, zone, disk, snapshot); err != tt.expectedError {
				t.Errorf("%v failed exp:%v got: %v", tt.name, tt.expectedError, err)
			}
		})
	}
}
