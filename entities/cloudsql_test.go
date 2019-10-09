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
			instance:         "unexisting",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: nil,
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:           "unexisting",
				Project:        "project1",
				ConnectionName: "project1" + ":" + "us-central1" + ":" + "unexisting",
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

			if tt.expectedError != nil && err != tt.expectedError {
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
			name:             "close public access in a existing database",
			instance:         "instance1",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: nil,
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:           "instance1",
				Project:        "project1",
				ConnectionName: "project1:us-central1:instance1",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						AuthorizedNetworks: []*sqladmin.AclEntry{
							&sqladmin.AclEntry{
								Value: "1.0.0.0/0",
							},
						},
					},
				},
			},
		},
		{
			name:             "close public access in a nonexisting database",
			instance:         "unexisting",
			projectID:        "project1",
			region:           "us-central1",
			expectedError:    nil,
			expectedResponse: nil,
			expectedRequest: &sqladmin.DatabaseInstance{
				Name:           "unexisting",
				Project:        "project1",
				ConnectionName: "project1:us-central1:unexisting",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						AuthorizedNetworks: []*sqladmin.AclEntry{
							&sqladmin.AclEntry{
								Value: "1.0.0.0/0",
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
			r, err := c.ClosePublicAccess(ctx, tt.projectID, tt.instance, tt.region)

			if diff := cmp.Diff(sqlAdminStub.SavedInstanceUpdated, tt.expectedRequest); diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}

			if tt.expectedError != nil && err != tt.expectedError {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedError, err)
			}

			if tt.expectedError == nil && r == nil {
				t.Errorf("%v failed exp:%v got:%v", tt.name, tt.expectedResponse, r)
			}
		})
	}
}
