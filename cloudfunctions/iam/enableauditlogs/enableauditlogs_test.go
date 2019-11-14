package enableauditlogs

//  Copyright 2019 Google LLC
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  	https://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

import (
	"context"
	"testing"

	"github.com/pkg/errors"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestReadFinding(t *testing.T) {
	const (
		loggingScanner = `{
		"finding": {
			"name": "organizations/1055058813388/sources/1986930501971458034/findings/1c35bd4b4f6d7145e441f2965c32f074",
			"parent": "organizations/1055058813388/sources/1986930501971458034",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/108906606255",
			"state": "ACTIVE",
			"category": "AUDIT_LOGGING_DISABLED",
			"externalUri": "https://console.cloud.google.com/iam-admin/audit/allservices?project=fake-project",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_audit_logging_disabled\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "Low",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/audit/allservices?project=fake-project and under \"LOG TYPE\" select \"Admin read\", \"Data read\", and \"Data write\", and then click \"SAVE\". Make sure there are no exempted users configured.",
				"ProjectId": "fake-project",
				"AssetCreationTime": "2019-10-22T15:13:39.305Z",
				"ScannerName": "LOGGING_SCANNER",
				"ScanRunId": "2019-10-22T14:01:08.832-07:00",
				"Explanation": "You should enable Cloud Audit Logging for all services, to track all Admin activities including read and write access to user data."
			},
			"securityMarks": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/1c35bd4b4f6d7145e441f2965c32f074/securityMarks"
			},
			"eventTime": "2019-10-22T21:01:08.832Z",
			"createTime": "2019-10-22T21:01:39.098Z",
			"assetId": "organizations/1055058813388/assets/11190834741917282179",
			"assetDisplayName": "fake-project"
		   }
		}`

		unknownCategoryScanner = `{
		"finding": {
				"resourceName": "//cloudresourcemanager.googleapis.com/projects/108906606255",
				"state": "ACTIVE",
				"category": "UNK",
				"sourceProperties": {"ProjectId": "fake-project"}
			}
		}`
		unknownProjectIDScanner = `{
		"finding": {
				"resourceName": "//cloudresourcemanager.googleapis.com/projects/108906606255",
				"state": "ACTIVE",
				"category": "AUDIT_LOGGING_DISABLED",
				"sourceProperties": {"ProjectId": ""}
			}
		}`

		inactiveFinding = `{
		"finding": {
			"name": "organizations/1055058813388/sources/1986930501971458034/findings/1c35bd4b4f6d7145e441f2965c32f074",
			"parent": "organizations/1055058813388/sources/1986930501971458034",
			"resourceName": "//cloudresourcemanager.googleapis.com/projects/108906606255",
			"state": "INACTIVE",
			"category": "AUDIT_LOGGING_DISABLED",
			"externalUri": "https://console.cloud.google.com/iam-admin/audit/allservices?project=fake-project",
			"sourceProperties": {
				"ReactivationCount": 0,
				"ExceptionInstructions": "Add the security mark \"allow_audit_logging_disabled\" to the asset with a value of \"true\" to prevent this finding from being activated again.",
				"SeverityLevel": "Low",
				"Recommendation": "Go to https://console.cloud.google.com/iam-admin/audit/allservices?project=fake-project and under \"LOG TYPE\" select \"Admin read\", \"Data read\", and \"Data write\", and then click \"SAVE\". Make sure there are no exempted users configured.",
				"ProjectId": "fake-project",
				"AssetCreationTime": "2019-10-22T15:13:39.305Z",
				"ScannerName": "LOGGING_SCANNER",
				"ScanRunId": "2019-10-22T14:01:08.832-07:00",
				"Explanation": "You should enable Cloud Audit Logging for all services, to track all Admin activities including read and write access to user data."
			},
			"securityMarks": {
				"name": "organizations/1055058813388/sources/1986930501971458034/findings/1c35bd4b4f6d7145e441f2965c32f074/securityMarks"
			},
			"eventTime": "2019-10-22T21:01:08.832Z",
			"createTime": "2019-10-22T21:01:39.098Z",
			"assetId": "organizations/1055058813388/assets/11190834741917282179",
			"assetDisplayName": "fake-project"
		   }
		}`
	)
	tests := []struct {
		name           string
		message        []byte
		expectedResult *Values
		expectedError  error
	}{
		{name: "test enable audit logs", message: []byte(loggingScanner), expectedResult: &Values{ProjectID: "fake-project"}, expectedError: nil},
		{name: "test enable audit logs with empty projectID", message: []byte(unknownProjectIDScanner), expectedResult: nil, expectedError: services.ErrValueNotFound},
		{name: "test enable audit logs invalid message json", message: []byte(`{{"elem": 1}, {"elem": 2}}`), expectedResult: nil, expectedError: services.ErrUnmarshal},
		{name: "test enable audit logs unknown category", message: []byte(unknownCategoryScanner), expectedResult: nil, expectedError: services.ErrValueNotFound},
		{name: "test enable audit logs inactive finding", message: []byte(inactiveFinding), expectedResult: nil, expectedError: services.ErrUnsupportedFinding},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ReadFinding(tt.message)
			if errors.Cause(err) != tt.expectedError {
				t.Errorf("%v failed exp:%q got:%q", tt.name, tt.expectedError, err)
			}
			if diff := cmp.Diff(resp, tt.expectedResult); diff != "" {
				t.Errorf("%v failed expectedResult enable auditlogs - exp:%v got:%v", tt.name, tt.expectedResult, resp)
			}
		})
	}
}

func TestExecuteEnableDataAccessAuditLogs(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
		message        []byte
		expectedResult []*crm.AuditConfig
	}{
		{
			name: "test enable audit logs",
			expectedResult: []*crm.AuditConfig{
				{AuditLogConfigs: []*crm.AuditLogConfig{
					{LogType: "ADMIN_READ"},
					{LogType: "DATA_READ"},
					{LogType: "DATA_WRITE"},
				},
					Service: "allServices",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			required := &Values{ProjectID: "fake-project"}
			policy := &crm.Policy{AuditConfigs: []*crm.AuditConfig{}}
			entity := setupAuditLogs(policy)
			if err := Execute(ctx, required, &Services{
				Configuration: entity.Configuration,
				Resource:      entity.Resource,
				Logger:        entity.Logger,
			}); err != nil {
				t.Errorf("%s failed to enable audi logs :%q", tt.name, err)
			}
			if diff := cmp.Diff(policy.AuditConfigs, tt.expectedResult); diff != "" {
				t.Errorf("%v failed to update audit config logs policy \n exp:%v\n got:%v",
					tt.name, tt.expectedResult, policy.AuditConfigs)
			}
		})
	}
}

func setupAuditLogs(mock *crm.Policy) *services.Global {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	config := services.Configuration{
		EnableAuditLogs: &services.EnableAuditLogs{
			Resources: &services.Resources{
				FolderIDs: []string{"593987969559"}},
		},
	}
	return &services.Global{
		Resource: services.NewResource(
			&stubs.ResourceManagerStub{
				GetPolicyResponse:   mock,
				GetAncestryResponse: services.CreateAncestors([]string{"folder/593987969559"}),
			},
			&stubs.StorageStub{}),
		Configuration: &config,
		Logger:        log,
	}
}
