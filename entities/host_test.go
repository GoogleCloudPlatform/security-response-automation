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

	"google.golang.org/api/compute/v1"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
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

func TestRemoveExternalIPFromInstanceNetworkInterfaces(t *testing.T) {
	nic0 := compute.NetworkInterface{
		Name: "nic0",
		AccessConfigs: []*compute.AccessConfig{
			&compute.AccessConfig{
				Name:  "External NAT",
				NatIP: "35.192.206.126",
				Type:  "ONE_TO_ONE_NAT",
			},
		},
	}

	nic1 := compute.NetworkInterface{
		Name: "nic1",
		AccessConfigs: []*compute.AccessConfig{
			&compute.AccessConfig{
				Name:  "External NAT",
				NatIP: "34.70.92.164",
				Type:  "ONE_TO_ONE_NAT",
			},
		},
	}

	nic2 := compute.NetworkInterface{
		Name: "nic2",
		AccessConfigs: []*compute.AccessConfig{
			&compute.AccessConfig{
				Name:  "External NAT",
				NatIP: "34.70.92.170",
				Type:  "ONE_TO_ONE_NAT",
			},
			&compute.AccessConfig{
				Name:  "External NAT",
				NatIP: "34.192.92.171",
				Type:  "ONE_TO_ONE_NAT",
			},
		},
	}

	tests := []struct {
		name         string
		project      string
		zone         string
		instance     string
		stubInstance *compute.Instance
	}{
		{
			name:     "remove instance's external ips",
			project:  "test-project",
			zone:     "test-zone",
			instance: "test-instance",
			stubInstance: &compute.Instance{
				NetworkInterfaces: []*compute.NetworkInterface{
					&nic0,
					&nic1,
					&nic2,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			computeStub := &stubs.ComputeStub{
				StubbedInstance: test.stubInstance,
			}
			host := NewHost(computeStub)
			err := host.RemoveExternalIPFromInstanceNetworkInterfaces(ctx, test.project, test.zone, test.instance)
			if err != nil {
				t.Errorf("%v failed, err: %+v", test.name, err)
			}
		})
	}
}
