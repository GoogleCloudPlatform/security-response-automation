package entities

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

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestEnforceSSLConnection(t *testing.T) {
	tests := []struct {
		name             string
		instance         string
		project          string
		region           string
		expectedError    error
		expectedResponse *sqladmin.Operation
	}{

		{
			name:             "enforce ssl connection in a existing database",
			instance:         "instance1",
			project:          "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: nil,
		},
		{
			name:             "enforce ssl connection in a nonexisting database",
			instance:         "instance1",
			project:          "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sqlAdminStub := &stubs.SQLAdminStub{}
			ctx := context.Background()
			c := NewCloudSQL(sqlAdminStub)
			r, err := c.EnforceSSLConnection(ctx, tt.project, tt.instance, tt.region)

			if tt.expectedError != nil && err != tt.expectedError {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if tt.expectedError == nil && r == nil {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, r)
			}
		})
	}
}
