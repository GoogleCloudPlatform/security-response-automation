package sqlscanner

import (
	"testing"

	"golang.org/x/xerrors"
)

func TestReadFindingUpdatePassword(t *testing.T) {
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
	)
	for _, tt := range []struct {
		name, instanceName, projectID, host, userName string
		bytes                                         []byte
		expectedError                                 error
	}{
		{name: "read", projectID: "threat-auto-tests-07102019", instanceName: "test-no-password", host: "%", userName: "root", bytes: []byte(noRootPassword), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			values, _ := r.UpdatePassword()
			if err == nil && r != nil && values.InstanceName != tt.instanceName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.InstanceName, tt.instanceName)
			}
			if err == nil && r != nil && values.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
			}
			if err == nil && r != nil && values.Host != tt.host {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.Host, tt.host)
			}
			if err == nil && r != nil && values.UserName != tt.userName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.UserName, tt.userName)
			}
			if err == nil && r != nil && values.Password == "" {
				t.Errorf("%s failed: got:%q", tt.name, values.Password)
			}
		})
	}
}

func TestReadFindingRequireSSL(t *testing.T) {
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
	)
	for _, tt := range []struct {
		name, InstanceName, projectID string
		bytes                         []byte
		expectedError                 error
	}{
		{name: "read", projectID: "sha-resources-20191002", InstanceName: "public-sql-instance", bytes: []byte(enforceSSL), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			values := r.RequireSSL()
			if err == nil && r != nil && values.InstanceName != tt.InstanceName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.InstanceName, tt.InstanceName)
			}
			if err == nil && r != nil && values.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
			}
		})
	}
}

func TestReadFindingRemovePublic(t *testing.T) {
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
	)
	for _, tt := range []struct {
		name, InstanceName, projectID string
		bytes                         []byte
		expectedError                 error
	}{
		{name: "read", projectID: "sha-resources-20191002", InstanceName: "public-sql-instance", bytes: []byte(openCloudSQL), expectedError: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := New(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			values := r.RemovePublic()
			if err == nil && r != nil && values.InstanceName != tt.InstanceName {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.InstanceName, tt.InstanceName)
			}
			if err == nil && r != nil && values.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, values.ProjectID, tt.projectID)
			}
		})
	}
}
