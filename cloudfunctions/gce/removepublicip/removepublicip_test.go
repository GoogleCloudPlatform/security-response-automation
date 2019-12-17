package removepublicip

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

	"github.com/google/go-cmp/cmp"
	compute "google.golang.org/api/compute/v1"

	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
)

func TestRemovePublicIP(t *testing.T) {
	ctx := context.Background()

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

	test := []struct {
		name                         string
		instance                     *compute.Instance
		expectedDeletedAccessConfigs []stubs.NetworkAccessConfigStub
	}{
		{
			name: "remove public ip",
			instance: &compute.Instance{
				NetworkInterfaces: []*compute.NetworkInterface{
					&externalNic0,
				},
			},
			expectedDeletedAccessConfigs: []stubs.NetworkAccessConfigStub{
				{
					NetworkInterfaceName: "nic0",
					AccessConfigName:     "External NAT",
				},
			},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, computeStub := setupRemovePublicIP()
			computeStub.StubbedInstance = tt.instance
			values := &Values{
				ProjectID:    "project-id",
				InstanceZone: "instance-zone",
				InstanceID:   "instance-id",
			}

			if err := Execute(ctx, values, &Services{
				Host:     svcs.Host,
				Resource: svcs.Resource,
				Logger:   svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to remove public ip :%q", tt.name, err)
			}

			if diff := cmp.Diff(tt.expectedDeletedAccessConfigs, computeStub.DeletedAccessConfigs); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}

func setupRemovePublicIP() (*services.Global, *stubs.ComputeStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	computeStub := &stubs.ComputeStub{}
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := services.NewResource(crmStub, storageStub)
	h := services.NewHost(computeStub)
	return &services.Global{Logger: log, Host: h, Resource: res}, computeStub
}
