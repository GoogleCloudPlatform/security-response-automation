package requiressl

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
	sqladmin "google.golang.org/api/sqladmin/v1beta4"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/services"
)

func TestReadFinding(t *testing.T) {
	const (
		enforceSSL = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/119612413569/sources/7086426792249889955/findings/00079ac439b9c80604b895289fd0686c",
				"parent": "organizations/119612413569/sources/7086426792249889955",
				"resourceName": "//cloudsql.googleapis.com/projects/sha-resources-20191002/instances/public-sql-instance",
				"state": "ACTIVE",
				"category": "SSL_NOT_ENFORCED",
				"externalUri": "https://console.cloud.google.com/sql/instances/public-sql-instance/connections?project=sha-resources-20191002",
				"sourceProperties": {
				  "ReactivationCount": 0,
				  "AssetSettings": "{\"activationPolicy\":\"ALWAYS\",\"backupConfiguration\":{\"binaryLogEnabled\":true,\"enabled\":true,\"kind\":\"sql#backupConfiguration\",\"startTime\":\"17:00\"},\"dataDiskSizeGb\":\"10\",\"dataDiskType\":\"PD_SSD\",\"ipConfiguration\":{\"authorizedNetworks\":[{\"kind\":\"sql#aclEntry\",\"name\":\"public-sql-network\",\"value\":\"0.0.0.0/0\"}],\"ipv4Enabled\":true},\"kind\":\"sql#settings\",\"locationPreference\":{\"kind\":\"sql#locationPreference\",\"zone\":\"us-central1-f\"},\"maintenanceWindow\":{\"day\":0.0,\"hour\":0.0,\"kind\":\"sql#maintenanceWindow\"},\"pricingPlan\":\"PER_USE\",\"replicationType\":\"SYNCHRONOUS\",\"settingsVersion\":\"6\",\"storageAutoResize\":true,\"storageAutoResizeLimit\":\"0\",\"tier\":\"db-n1-standard-1\"}",
				  "ExceptionInstructions": "Add the security mark \"allow_ssl_not_enforced\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				  "SeverityLevel": "High",
				  "Recommendation": "Go to https://console.cloud.google.com/sql/instances/public-sql-instance/connections?project=sha-resources-20191002 and click the \"Allow only SSL connections\" button.",
				  "ProjectId": "sha-resources-20191002",
				  "AssetCreationTime": "2019-10-03T13:58:45.428Z",
				  "ScannerName": "SQL_SCANNER",
				  "ScanRunId": "2019-10-25T16:20:25.28-07:00",
				  "Explanation": "To avoid leaking sensitive data in transit through unencrypted communications, all incoming connections to your SQL database instance should use SSL. Learn more at: https://cloud.google.com/sql/docs/mysql/configure-ssl-instance"
				},
				"securityMarks": {
				  "name": "organizations/119612413569/sources/7086426792249889955/findings/00079ac439b9c80604b895289fd0686c/securityMarks"
				},
				"eventTime": "2019-10-25T23:20:25.280Z",
				"createTime": "2019-10-03T17:20:24.389Z"
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
		{name: "read", projectID: "sha-resources-20191002", InstanceName: "public-sql-instance", bytes: []byte(enforceSSL), expectedError: nil},
		{name: "wrong category", projectID: "", InstanceName: "", bytes: []byte(wrongCategoryFinding), expectedError: services.ErrUnsupportedFinding},
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

func TestCloudSQLRequireSSL(t *testing.T) {
	ctx := context.Background()
	test := []struct {
		name            string
		folderIDs       []string
		ancestry        *crm.GetAncestryResponse
		expectedRequest *sqladmin.DatabaseInstance
	}{
		{
			name:      "enforce ssl on sql instance",
			folderIDs: []string{"123"},
			ancestry:  services.CreateAncestors([]string{"folder/123"}),
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:    "public-sql-instance",
				Project: "sha-resources-20191002",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						RequireSsl: true,
					},
				},
			},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, sqlStub, crmStub := cloudSQLRequireSSL(tt.folderIDs)
			crmStub.GetAncestryResponse = tt.ancestry
			values := &Values{
				ProjectID:    "sha-resources-20191002",
				InstanceName: "public-sql-instance",
			}
			if err := Execute(ctx, values, &Services{
				Configuration: svcs.Configuration,
				CloudSQL:      svcs.CloudSQL,
				Resource:      svcs.Resource,
				Logger:        svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to enforce ssl in the instance :%q", tt.name, err)
			}

			if diff := cmp.Diff(sqlStub.SavedInstanceUpdated, tt.expectedRequest); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedRequest, sqlStub.SavedInstanceUpdated)
			}
		})
	}
}

func cloudSQLRequireSSL(folderIDs []string) (*services.Global, *stubs.CloudSQL, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	sqlStub := &stubs.CloudSQL{}
	sql := services.NewCloudSQL(sqlStub)
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := services.NewResource(crmStub, storageStub)
	conf := &services.Configuration{
		CloudSQLRequireSSL: &services.CloudSQLRequireSSL{
			Resources: &services.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &services.Global{Logger: log, Configuration: conf, CloudSQL: sql, Resource: res}, sqlStub, crmStub
}
