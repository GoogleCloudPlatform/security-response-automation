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
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestUpdatePassword(t *testing.T) {
	ctx := context.Background()
	test := []struct {
		name            string
		expectedRequest *sqladmin.User
	}{
		{
			name: "update root password",
			expectedRequest: &sqladmin.User{
				Password: "4a542dd833d9f8a7600b13cd281d00cf2b0a5610e825ff931260b2911bef95b5",
			},
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, sqlStub := updatePasswordSetup()
			values := &Values{
				ProjectID:    "threat-auto-tests-07102019",
				InstanceName: "test-no-password",
				Host:         "%",
				UserName:     "root",
				Password:     "4a542dd833d9f8a7600b13cd281d00cf2b0a5610e825ff931260b2911bef95b5",
			}
			if err := Execute(ctx, values, &Services{
				CloudSQL: svcs.CloudSQL,
				Resource: svcs.Resource,
				Logger:   svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to update root password for instance :%q", tt.name, err)
			}

			if diff := cmp.Diff(sqlStub.UpdatedUser, tt.expectedRequest); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedRequest, sqlStub.SavedInstanceUpdated)
			}
		})
	}
}

func updatePasswordSetup() (*services.Global, *stubs.CloudSQL) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	sqlStub := &stubs.CloudSQL{}
	sql := services.NewCloudSQL(sqlStub)
	storageStub := &stubs.StorageStub{}
	crmStub := &stubs.ResourceManagerStub{}
	res := services.NewResource(crmStub, storageStub)
	return &services.Global{Logger: log, CloudSQL: sql, Resource: res}, sqlStub
}
