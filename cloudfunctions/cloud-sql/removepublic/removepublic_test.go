package removepublic

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

	"cloud.google.com/go/pubsub"
	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/entities/helpers"
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestReadFinding(t *testing.T) {
	const (
		openCloudSQL = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/119612413569/sources/7086426792249889955/findings/b7a48a4162ca2fb64627dd0a9a9756e1",
				"parent": "organizations/119612413569/sources/7086426792249889955",
				"resourceName": "//cloudsql.googleapis.com/projects/sha-resources-20191002/instances/public-sql-instance",
				"state": "ACTIVE",
				"category": "PUBLIC_SQL_INSTANCE",
				"externalUri": "https://console.cloud.google.com/sql/instances/public-sql-instance/connections?project=sha-resources-20191002",
				"sourceProperties": {
				  "ReactivationCount": 0,
				  "AssetSettings": "{\"activationPolicy\":\"NEVER\",\"backupConfiguration\":{\"binaryLogEnabled\":true,\"enabled\":true,\"kind\":\"sql#backupConfiguration\",\"startTime\":\"17:00\"},\"dataDiskSizeGb\":\"10\",\"dataDiskType\":\"PD_SSD\",\"ipConfiguration\":{\"authorizedNetworks\":[{\"kind\":\"sql#aclEntry\",\"name\":\"public-sql-network\",\"value\":\"0.0.0.0/0\"}],\"ipv4Enabled\":true},\"kind\":\"sql#settings\",\"locationPreference\":{\"kind\":\"sql#locationPreference\",\"zone\":\"us-central1-f\"},\"maintenanceWindow\":{\"day\":0.0,\"hour\":0.0,\"kind\":\"sql#maintenanceWindow\"},\"pricingPlan\":\"PER_USE\",\"replicationType\":\"SYNCHRONOUS\",\"settingsVersion\":\"3\",\"storageAutoResize\":true,\"storageAutoResizeLimit\":\"0\",\"tier\":\"db-n1-standard-1\"}",
				  "ExceptionInstructions": "Add the security mark \"allow_public_sql_instance\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				  "SeverityLevel": "High",
				  "Recommendation": "Restrict the authorized networks at https://console.cloud.google.com/sql/instances/public-sql-instance/connections?project=sha-resources-20191002.",
				  "ProjectId": "sha-resources-20191002",
				  "AssetCreationTime": "2019-10-03T13:58:45.428Z",
				  "ScannerName": "SQL_SCANNER",
				  "ScanRunId": "2019-10-11T16:20:26.221-07:00",
				  "Explanation": "You have added 0.0.0.0/0 as an allowed network. This prefix will allow any IPv4 client to pass the network firewall and make login attempts to your instance, including clients you did not intend to allow. Clients still need valid credentials to successfully log in to your instance. Learn more at: https://cloud.google.com/sql/docs/mysql/configure-ip"
				},
				"securityMarks": {
				  "name": "organizations/119612413569/sources/7086426792249889955/findings/b7a48a4162ca2fb64627dd0a9a9756e1/securityMarks"
				},
				"eventTime": "2019-10-11T23:20:26.221Z",
				"createTime": "2019-10-03T17:20:24.331Z"
			 }
		}`

		wrongCategoryFinding = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e",
				"parent": "organizations/1055058813388/sources/1986930501971458034",
				"resourceName": "//compute.googleapis.com/projects/onboarding-project/global/firewalls/6190685430815455733",
				"state": "ACTIVE",
				"category": "CLOSED_FIREWALL",
				"externalUri": "https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-project",
				"sourceProperties": {
					"ReactivationCount": 0.0,
					"Allowed": "[{\"IPProtocol\":\"tcp\",\"ipProtocol\":\"tcp\",\"port\":[\"80\"],\"ports\":[\"80\"]}]",
					"ExceptionInstructions": "Add the security mark \"allow_open_firewall\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Restrict the firewall rules at: https://console.cloud.google.com/networking/firewalls/details/default-allow-http?project\u003donboarding-project",
					"AllowedIpRange": "All",
					"ActivationTrigger": "Allows all IP addresses",
					"ProjectId": "onboarding-project",
					"DeactivationReason": "The asset was deleted.",
					"SourceRange": "[\"0.0.0.0/0\"]",
					"AssetCreationTime": "2019-08-21t06:28:58.140-07:00",
					"ScannerName": "FIREWALL_SCANNER",
					"ScanRunId": "2019-09-17T07:10:21.961-07:00",
					"Explanation": "Firewall rules that allow connections from all IP addresses or on all ports may expose resources to attackers."
				},
				"securityMarks": {
					"name": "organizations/1055058813388/sources/1986930501971458034/findings/cea981dd340112213827902b408b497e/securityMarks",
					"marks": {
						"sccquery94c23b35ea0b4f8388268415a0dc6c1b": "true"
					}
				},
				"eventTime": "2019-09-19T16:58:39.276Z",
				"createTime": "2019-09-16T22:11:59.977Z"
			}
		}`
	)
	for _, tt := range []struct {
		name, InstanceName, projectID string
		bytes                         []byte
		expectedError                 error
	}{
		{name: "read", projectID: "sha-resources-20191002", InstanceName: "public-sql-instance", bytes: []byte(openCloudSQL), expectedError: nil},
		{name: "wrong category", projectID: "", InstanceName: "", bytes: []byte(wrongCategoryFinding), expectedError: entities.ErrValueNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r.InstanceName != tt.InstanceName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.InstanceName, tt.InstanceName)
			}
			if err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
			}
		})
	}
}

func TestCloseCloudSQL(t *testing.T) {
	ctx := context.Background()
	test := []struct {
		name                    string
		folderIDs               []string
		instanceDetailsResponse *sqladmin.DatabaseInstance
		ancestry                *crm.GetAncestryResponse
		finding                 pubsub.Message
		expectedRequest         *sqladmin.DatabaseInstance
	}{
		{
			name:      "close public ip on sql instance",
			folderIDs: []string{"123"},
			ancestry:  helpers.CreateAncestors([]string{"folder/123"}),
			instanceDetailsResponse: &sqladmin.DatabaseInstance{
				Name:    "public-sql-instance",
				Project: "sha-resources-20191002",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						AuthorizedNetworks: []*sqladmin.AclEntry{
							{
								Value: "0.0.0.0/0",
							},
							{
								Value: "199.27.199.0/24",
							},
						},
					},
				},
			},
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:    "public-sql-instance",
				Project: "sha-resources-20191002",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						AuthorizedNetworks: []*sqladmin.AclEntry{
							{
								Value: "199.27.199.0/24",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, sqlStub, crmStub := closeSQLSetup(tt.folderIDs)
			sqlStub.InstanceDetailsResponse = tt.instanceDetailsResponse
			crmStub.GetAncestryResponse = tt.ancestry
			required := &Required{
				ProjectID:    "sha-resources-20191002",
				InstanceName: "public-sql-instance",
			}
			if err := Execute(ctx, required, ent); err != nil {
				t.Errorf("%s failed to remove public ip from instance :%q", tt.name, err)
			}

			if diff := cmp.Diff(sqlStub.SavedInstanceUpdated, tt.expectedRequest); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedRequest, sqlStub.SavedInstanceUpdated)
			}
		})
	}
}

func closeSQLSetup(folderIDs []string) (*entities.Entity, *stubs.CloudSQL, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := entities.NewLogger(loggerStub)
	sqlStub := &stubs.CloudSQL{}
	sql := entities.NewCloudSQL(sqlStub)
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := entities.NewResource(crmStub, storageStub)
	conf := &entities.Configuration{
		CloseCloudSQL: &entities.CloseCloudSQL{
			Resources: &entities.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &entities.Entity{Logger: log, Configuration: conf, CloudSQL: sql, Resource: res}, sqlStub, crmStub
}
