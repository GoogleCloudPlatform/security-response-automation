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
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	compute "google.golang.org/api/compute/v1"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/entities/helpers"
)

func TestReadFinding(t *testing.T) {
	const (
		publicIPAddressFinding = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/d7ef72093c8c1e4c135d4c43fa847b83",
				"parent": "organizations/1055058813388/sources/1986930501971458034",
				"resourceName": "//compute.googleapis.com/projects/sec-automation-dev/zones/us-central1-a/instances/4312755253150365851",
				"state": "ACTIVE",
				"category": "PUBLIC_IP_ADDRESS",
				"externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/remove-public-ip-test-vm",
				"sourceProperties": {
				  "ReactivationCount": 0,
				  "ExceptionInstructions": "Add the security mark \"allow_public_ip_address\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				  "SeverityLevel": "High",
				  "Recommendation": "If this is unintended, please go to https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/remove-public-ip-test-vm and click \"Edit\". For each interface under the \"Network interfaces\" heading, set \"External IP\" to \"None\" or \"Ephemeral\", then click \"Done\" and \"Save\".  If you would like to learn more about securing access to your infrastructure, see https://cloud.google.com/solutions/connecting-securely.",
				  "ProjectId": "sec-automation-dev",
				  "AssetCreationTime": "2019-10-04T10:50:45.017-07:00",
				  "ScannerName": "COMPUTE_INSTANCE_SCANNER",
				  "ScanRunId": "2019-10-10T00:01:51.204-07:00",
				  "Explanation": "To reduce the attack surface, avoid assigning public IP addresses to your VMs."
				},
				"securityMarks": {
				  "name": "organizations/1055058813388/sources/1986930501971458034/findings/d7ef72093c8c1e4c135d4c43fa847b83/securityMarks",
				  "marks": {
					"kieras-test": "true",
					"kieras-test2": "true"
				  }
				},
				"eventTime": "2019-10-10T07:01:51.204Z",
				"createTime": "2019-10-04T19:02:25.582Z"
			}
		}`

		wrongCategoryFinding = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/d7ef72093c8c1e4c135d4c43fa847b83",
				"parent": "organizations/1055058813388/sources/1986930501971458034",
				"resourceName": "//compute.googleapis.com/projects/sec-automation-dev/zones/us-central1-a/instances/4312755253150365851",
				"state": "ACTIVE",
				"category": "NOT_PUBLIC_IP_ADDRESS",
				"externalUri": "https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/remove-public-ip-test-vm",
				"sourceProperties": {
				  "ReactivationCount": 0,
				  "ExceptionInstructions": "Add the security mark \"allow_public_ip_address\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				  "SeverityLevel": "High",
				  "Recommendation": "If this is unintended, please go to https://console.cloud.google.com/compute/instancesDetail/zones/us-central1-a/instances/remove-public-ip-test-vm and click \"Edit\". For each interface under the \"Network interfaces\" heading, set \"External IP\" to \"None\" or \"Ephemeral\", then click \"Done\" and \"Save\".  If you would like to learn more about securing access to your infrastructure, see https://cloud.google.com/solutions/connecting-securely.",
				  "ProjectId": "sec-automation-dev",
				  "AssetCreationTime": "2019-10-04T10:50:45.017-07:00",
				  "ScannerName": "COMPUTE_INSTANCE_SCANNER",
				  "ScanRunId": "2019-10-10T00:01:51.204-07:00",
				  "Explanation": "To reduce the attack surface, avoid assigning public IP addresses to your VMs."
				},
				"securityMarks": {
				  "name": "organizations/1055058813388/sources/1986930501971458034/findings/d7ef72093c8c1e4c135d4c43fa847b83/securityMarks",
				  "marks": {
					"kieras-test": "true",
					"kieras-test2": "true"
				  }
				},
				"eventTime": "2019-10-10T07:01:51.204Z",
				"createTime": "2019-10-04T19:02:25.582Z"
			}
		}`
	)
	for _, tt := range []struct {
		name          string
		projectID     string
		instanceZone  string
		instanceID    string
		bytes         []byte
		expectedError error
	}{
		{name: "read", projectID: "sec-automation-dev", instanceZone: "us-central1-a", instanceID: "4312755253150365851", bytes: []byte(publicIPAddressFinding), expectedError: nil},
		{name: "wrong category", projectID: "", instanceZone: "", instanceID: "", bytes: []byte(wrongCategoryFinding), expectedError: entities.ErrValueNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
			}
			if err == nil && r.InstanceZone != tt.instanceZone {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.InstanceZone, tt.instanceZone)
			}
			if err == nil && r.InstanceID != tt.instanceID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.InstanceID, tt.instanceID)
			}
		})
	}
}

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
		folderIDs                    []string
		ancestry                     *crm.GetAncestryResponse
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
			folderIDs: []string{"123"},
			ancestry:  helpers.CreateAncestors([]string{"folder/123"}),
		},
		{
			name: "no valid folder",
			instance: &compute.Instance{
				NetworkInterfaces: []*compute.NetworkInterface{
					&externalNic0,
				},
			},
			expectedDeletedAccessConfigs: nil,
			folderIDs:                    []string{"456"},
			ancestry:                     helpers.CreateAncestors([]string{"folder/123"}),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, computeStub, crmStub := setupRemovePublicIP(tt.folderIDs)
			computeStub.StubbedInstance = tt.instance
			crmStub.GetAncestryResponse = tt.ancestry
			required := &Required{
				ProjectID:    "project-id",
				InstanceZone: "instance-zone",
				InstanceID:   "instance-id",
			}

			if err := Execute(ctx, required, ent); err != nil {
				t.Errorf("%s failed to remove public ip :%q", tt.name, err)
			}

			if diff := cmp.Diff(tt.expectedDeletedAccessConfigs, computeStub.DeletedAccessConfigs); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}
}

func setupRemovePublicIP(folderIDs []string) (*entities.Entity, *stubs.ComputeStub, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := entities.NewLogger(loggerStub)
	computeStub := &stubs.ComputeStub{}
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := entities.NewResource(crmStub, storageStub)
	h := entities.NewHost(computeStub)
	conf := &entities.Configuration{
		RemovePublicIP: &entities.RemovePublicIP{
			Resources: &entities.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &entities.Entity{Logger: log, Host: h, Resource: res, Configuration: conf}, computeStub, crmStub
}
