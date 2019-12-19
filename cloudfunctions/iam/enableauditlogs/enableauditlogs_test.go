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

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	crm "google.golang.org/api/cloudresourcemanager/v1"
)

func TestExecuteEnableDataAccessAuditLogs(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name           string
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
				Resource: entity.Resource,
				Logger:   entity.Logger,
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
	return &services.Global{
		Resource: services.NewResource(
			&stubs.ResourceManagerStub{
				GetPolicyResponse: mock,
			},
			&stubs.StorageStub{}),
		Logger: log,
	}
}
