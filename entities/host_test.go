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
	"context"
	"testing"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	compute "google.golang.org/api/compute/v1"
)

func TestCreateDiskSnapshot(t *testing.T) {
	const (
		projectID = "test-project-id"
		zone      = "test-zone"
		disk      = "test-disk"
		snapshot  = "test-snapshot"
	)
	tests := []struct {
		name             string
		expectedError    error
		expectedResponse *compute.Snapshot
	}{
		{
			name:             "test",
			expectedError:    nil,
			expectedResponse: &compute.Snapshot{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			computeStub := &stubs.ComputeStub{}
			computeStub.SavedCreateSnapshots = make(map[string]compute.Snapshot)
			ctx := context.Background()
			h := NewHost(computeStub)
			if _, err := h.CreateDiskSnapshot(ctx, projectID, zone, disk, snapshot); err != tt.expectedError {
				t.Errorf("%v failed exp:%v got: %v", tt.name, tt.expectedError, err)
			}
		})
	}
}

func TestStopHost(t *testing.T) {
	const (
		projectID = "test-project-id"
		zone      = "test-zone"
		instance  = "test-instance"
	)
	tests := []struct {
		name             string
		expectedError    error
		expectedResponse *compute.Operation
	}{
		{
			name:             "TestStopHost",
			expectedError:    nil,
			expectedResponse: &compute.Operation{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			h := NewHost(&stubs.ComputeStub{})
			if _, err := h.StopComputeInstance(ctx, projectID, zone, instance); err != tt.expectedError {
				t.Errorf("%v failed exp:%v got: %v", tt.name, tt.expectedError, err)
			}
		})
	}
}
