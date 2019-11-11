package services

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

	"github.com/googlecloudplatform/security-response-automation/clients/stubs"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/api/compute/v1"
)

func TestCreateDiskSnapshot(t *testing.T) {
	const (
		projectID = "test-project-id"
		zone      = "test-zone"
		disk      = "test-disk"
		snapshot  = "test-snapshot"
	)
	tests := []struct {
		name                string
		expectedError       error
		expectedSnapshot    string
		expectedDescription string
	}{
		{
			name:                "test",
			expectedError:       nil,
			expectedSnapshot:    disk,
			expectedDescription: "Snapshot of " + disk,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			computeStub := &stubs.ComputeStub{
				SavedCreateSnapshots: make(map[string]compute.Snapshot),
			}
			ctx := context.Background()
			h := NewHost(computeStub)
			if err := h.CreateDiskSnapshot(ctx, projectID, zone, disk, snapshot); err != tt.expectedError {
				t.Errorf("%v failed exp:%v got: %v", tt.name, tt.expectedError, err)
			}
			if computeStub.SavedCreateSnapshots[disk].Description != tt.expectedDescription {
				t.Errorf("%s failed exp:%s got:%s", tt.name, tt.expectedDescription, computeStub.SavedCreateSnapshots[disk].Description)
			}
		})
	}
}

func TestRemoveExternalIPFromInstanceNetworkInterfaces(t *testing.T) {
	const (
		project  = "test-project"
		zone     = "test-zone"
		instance = "test-instance"
	)

	externalNic0 := compute.NetworkInterface{
		Name: "nic0",
		AccessConfigs: []*compute.AccessConfig{
			{
				Name:  "External NAT",
				NatIP: "35.192.206.126",
				Type:  "ONE_TO_ONE_NAT",
			},
		},
	}

	externalNic1 := compute.NetworkInterface{
		Name: "nic1",
		AccessConfigs: []*compute.AccessConfig{
			{
				Name:  "External NAT",
				NatIP: "34.70.92.170",
				Type:  "ONE_TO_ONE_NAT",
			},
		},
	}

	externalNic2UnknownType := compute.NetworkInterface{
		Name: "nic2",
		AccessConfigs: []*compute.AccessConfig{
			{
				Name:  "External NAT",
				NatIP: "34.192.92.171",
				Type:  "UNKNOWN",
			},
		},
	}

	tests := []struct {
		name                         string
		stubInstance                 *compute.Instance
		expectedDeletedAccessConfigs []stubs.NetworkAccessConfigStub
	}{
		{
			name: "remove the instance external ips with two network interfaces",
			stubInstance: &compute.Instance{
				NetworkInterfaces: []*compute.NetworkInterface{
					&externalNic0,
					&externalNic1,
				},
			},
			expectedDeletedAccessConfigs: []stubs.NetworkAccessConfigStub{
				{
					NetworkInterfaceName: "nic0",
					AccessConfigName:     "External NAT",
				},
				{
					NetworkInterfaceName: "nic1",
					AccessConfigName:     "External NAT",
				},
			},
		},
		{
			name: "don't remove the instance external ip with unknown access config type",
			stubInstance: &compute.Instance{
				NetworkInterfaces: []*compute.NetworkInterface{
					&externalNic2UnknownType,
				},
			},
			expectedDeletedAccessConfigs: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			computeStub := &stubs.ComputeStub{
				StubbedInstance: tt.stubInstance,
			}
			host := NewHost(computeStub)
			err := host.RemoveExternalIPs(ctx, project, zone, instance)
			if err != nil {
				t.Errorf("%v failed, err: %q", tt.name, err)
			}

			if diff := cmp.Diff(tt.expectedDeletedAccessConfigs, computeStub.DeletedAccessConfigs); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}

func TestRemoveExternalIPFromInstanceNetworkInterfacesFailing(t *testing.T) {
	const (
		project  = "test-project"
		zone     = "test-zone"
		instance = "test-instance"
	)

	externalNic0 := compute.NetworkInterface{
		Name: "nic0",
		AccessConfigs: []*compute.AccessConfig{
			{
				Name:  "External NAT",
				NatIP: "35.192.206.126",
				Type:  "ONE_TO_ONE_NAT",
			},
		},
	}

	tests := []struct {
		name                             string
		stubInstance                     *compute.Instance
		expectedDeletedAccessConfigs     []stubs.NetworkAccessConfigStub
		getInstanceCallShouldFail        bool
		deleteAccessConfigCallShouldFail bool
	}{
		{
			name: "fail to get instance when trying to remove external ip",
			stubInstance: &compute.Instance{
				NetworkInterfaces: []*compute.NetworkInterface{
					&externalNic0,
				},
			},
			expectedDeletedAccessConfigs:     nil,
			getInstanceCallShouldFail:        true,
			deleteAccessConfigCallShouldFail: false,
		},
		{
			name: "fail to delete access config",
			stubInstance: &compute.Instance{
				NetworkInterfaces: []*compute.NetworkInterface{
					&externalNic0,
				},
			},
			getInstanceCallShouldFail:        false,
			deleteAccessConfigCallShouldFail: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			computeStub := &stubs.ComputeStub{
				StubbedInstance:              tt.stubInstance,
				GetInstanceShouldFail:        tt.getInstanceCallShouldFail,
				DeleteAccessConfigShouldFail: tt.deleteAccessConfigCallShouldFail,
			}
			host := NewHost(computeStub)
			err := host.RemoveExternalIPs(ctx, project, zone, instance)
			if err == nil {
				t.Errorf("%q failed got:nil want:%q", tt.name, err)
			}
		})
	}
}
