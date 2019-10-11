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
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestEnforceSSLConnection(t *testing.T) {
	tests := []struct {
		name             string
		instance         string
		projectID        string
		region           string
		expectedError    error
		expectedResponse *sqladmin.Operation
		expectedRequest  *sqladmin.DatabaseInstance
	}{

		{
			name:             "enforce ssl connection in a existing database",
			instance:         "instance1",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: nil,
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:           "instance1",
				Project:        "project1",
				ConnectionName: "project1" + ":" + "us-central1" + ":" + "instance1",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						RequireSsl: true,
					},
				},
			},
		},
		{
			name:             "enforce ssl connection in a nonexisting database",
			instance:         "nonexisting",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    fmt.Errorf("the Cloud SQL instance does not exist"),
			expectedResponse: nil,
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:           "nonexisting",
				Project:        "project1",
				ConnectionName: "project1" + ":" + "us-central1" + ":" + "nonexisting",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						RequireSsl: true,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sqlAdminStub := &stubs.SQLAdminStub{}
			ctx := context.Background()
			c := NewCloudSQL(sqlAdminStub)
			r, err := c.EnforceSSLConnection(ctx, tt.projectID, tt.instance, tt.region)

			if diff := cmp.Diff(sqlAdminStub.SavedInstanceUpdated, tt.expectedRequest); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}

			if tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if tt.expectedError == nil && r == nil {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, r)
			}
		})
	}
}

func TestClosePublicAccess(t *testing.T) {
	tests := []struct {
		name             string
		instance         string
		projectID        string
		region           string
		expectedError    error
		expectedResponse *sqladmin.Operation
		expectedRequest  *sqladmin.DatabaseInstance
	}{
		{
			name:             "close public access in a nonexisting database",
			instance:         "nonexisting",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    fmt.Errorf("the Cloud SQL instance does not exist"),
			expectedResponse: nil,
			expectedRequest:  nil,
		},
		{
			name:             "close public access in a existing database with only one auth ip",
			instance:         "onepublicip",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: &sqladmin.Operation{},
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:    "onepublicip",
				Project: "project1",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						AuthorizedNetworks: nil,
						NullFields:         []string{"AuthorizedNetworks"},
					},
				},
			},
		},
		{
			name:             "close public access in a existing database with more than one auth ip",
			instance:         "instance1",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: &sqladmin.Operation{},
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:    "instance1",
				Project: "project1",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						AuthorizedNetworks: []*sqladmin.AclEntry{
							&sqladmin.AclEntry{
								Value: "199.27.199.0/24",
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sqlAdminStub := &stubs.SQLAdminStub{}
			ctx := context.Background()
			c := NewCloudSQL(sqlAdminStub)
			var databaseInstance, err = c.InstanceDetails(ctx, tt.projectID, tt.instance)

			if tt.expectedError != nil && tt.expectedError.Error() != err.Error() {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			r, err := c.ClosePublicAccess(ctx, tt.projectID, tt.instance, databaseInstance)

			if diff := cmp.Diff(sqlAdminStub.SavedInstanceUpdated, tt.expectedRequest); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
			if tt.expectedError != nil && err.Error() != tt.expectedError.Error() {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if diff := cmp.Diff(r, tt.expectedResponse); diff != "" {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, r)
			}

		})
	}
}
