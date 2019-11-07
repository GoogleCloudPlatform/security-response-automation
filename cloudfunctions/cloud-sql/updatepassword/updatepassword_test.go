package updatepassword

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
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/entities/helpers"
	"golang.org/x/xerrors"
	crm "google.golang.org/api/cloudresourcemanager/v1"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestReadFinding(t *testing.T) {
	const (
		noRootPassword = `{
			"notificationConfigName": "organizations/1055058813388/notificationConfigs/noticonf-active-001-id",
			"finding": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/986d52793c4aefc976dd2f35c14b7726",
				"parent": "organizations/1055058813388/sources/1986930501971458034",
				"resourceName": "//cloudsql.googleapis.com/projects/threat-auto-tests-07102019/instances/test-no-password",
				"state": "ACTIVE",
				"category": "SQL_NO_ROOT_PASSWORD",
				"externalUri": "https://console.cloud.google.com/sql/instances/test-no-password/users?project=threat-auto-tests-07102019",
				"sourceProperties": {
					"ReactivationCount": 0,
					"AssetSettings": "{\"activationPolicy\":\"ALWAYS\",\"availabilityType\":\"ZONAL\",\"backupConfiguration\":{\"binaryLogEnabled\":true,\"enabled\":true,\"kind\":\"sql#backupConfiguration\",\"startTime\":\"20:00\"},\"dataDiskSizeGb\":\"10\",\"dataDiskType\":\"PD_SSD\",\"ipConfiguration\":{\"ipv4Enabled\":true},\"kind\":\"sql#settings\",\"locationPreference\":{\"kind\":\"sql#locationPreference\",\"zone\":\"us-central1-f\"},\"maintenanceWindow\":{\"day\":0.0,\"hour\":0.0,\"kind\":\"sql#maintenanceWindow\"},\"pricingPlan\":\"PER_USE\",\"replicationType\":\"SYNCHRONOUS\",\"settingsVersion\":\"1\",\"storageAutoResize\":true,\"storageAutoResizeLimit\":\"0\",\"tier\":\"db-n1-standard-1\"}",
					"ExceptionInstructions": "Add the security mark \"allow_sql_no_root_password\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
					"SeverityLevel": "High",
					"Recommendation": "Go to https://console.cloud.google.com/sql/instances/test-no-password/users?project=threat-auto-tests-07102019 click the 3 dot icon next to the \"root\" user, select \"Change Password\", specify a new strong password, click \"OK\".",
					"ProjectId": "threat-auto-tests-07102019",
					"AssetCreationTime": "2019-10-31T13:13:33.146Z",
					"ScannerName": "SQL_SCANNER",
					"ScanRunId": "2019-10-31T15:20:22.425-07:00",
					"Explanation": "MySql database instances should have a strong password set for the root account."
				},
				"securityMarks": {
					"name": "organizations/1055058813388/sources/1986930501971458034/findings/986d52793c4aefc976dd2f35c14b7726/securityMarks"
				},
				"eventTime": "2019-10-31T22:20:22.425Z",
				"createTime": "2019-10-31T22:52:35.630Z"
			}
		}`

		wrongCategoryFinding = `{
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
	)
	for _, tt := range []struct {
		name, instanceName, projectID, host, userName string
		bytes                                         []byte
		expectedError                                 error
	}{
		{name: "read", projectID: "threat-auto-tests-07102019", instanceName: "test-no-password", host: "%", userName: "root", bytes: []byte(noRootPassword), expectedError: nil},
		{name: "wrong category", projectID: "", instanceName: "", host: "", userName: "", bytes: []byte(wrongCategoryFinding), expectedError: entities.ErrValueNotFound},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r.InstanceName != tt.instanceName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.InstanceName, tt.instanceName)
			}
			if err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
			}
			if err == nil && r.Host != tt.host {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.Host, tt.host)
			}
			if err == nil && r.UserName != tt.userName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.UserName, tt.userName)
			}
			if err == nil && r.Password == "" {
				t.Errorf("%s failed: got:%q", tt.name, r.Password)
			}
		})
	}
}

func TestUpdatePassword(t *testing.T) {
	ctx := context.Background()
	test := []struct {
		name            string
		folderIDs       []string
		ancestry        *crm.GetAncestryResponse
		expectedRequest *sqladmin.User
	}{
		{
			name:      "update root password",
			folderIDs: []string{"123"},
			ancestry:  helpers.CreateAncestors([]string{"folder/123"}),
			expectedRequest: &sqladmin.User{
				Password: "4a542dd833d9f8a7600b13cd281d00cf2b0a5610e825ff931260b2911bef95b5",
			},
		},
		{
			name:            "no valid folder",
			folderIDs:       []string{"456"},
			ancestry:        helpers.CreateAncestors([]string{"folder/123"}),
			expectedRequest: nil,
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, sqlStub, crmStub := updatePasswordSetup(tt.folderIDs)
			crmStub.GetAncestryResponse = tt.ancestry
			required := &Required{
				ProjectID:    "threat-auto-tests-07102019",
				InstanceName: "test-no-password",
				Host:         "%",
				UserName:     "root",
				Password:     "4a542dd833d9f8a7600b13cd281d00cf2b0a5610e825ff931260b2911bef95b5",
			}
			if err := Execute(ctx, required, ent); err != nil {
				t.Errorf("%s failed to update root password for instance :%q", tt.name, err)
			}

			if diff := cmp.Diff(sqlStub.UpdatedUser, tt.expectedRequest); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedRequest, sqlStub.SavedInstanceUpdated)
			}
		})
	}
}

func updatePasswordSetup(folderIDs []string) (*entities.Entity, *stubs.CloudSQL, *stubs.ResourceManagerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := entities.NewLogger(loggerStub)
	sqlStub := &stubs.CloudSQL{}
	sql := entities.NewCloudSQL(sqlStub)
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := entities.NewResource(crmStub, storageStub)
	conf := &entities.Configuration{
		UpdatePassword: &entities.UpdatePassword{
			Resources: &entities.Resources{
				FolderIDs: folderIDs,
			},
		},
	}
	return &entities.Entity{Logger: log, Configuration: conf, CloudSQL: sql, Resource: res}, sqlStub, crmStub
}
