package services

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
	sqladmin "google.golang.org/api/sqladmin/v1beta4"
)

func TestEnforceSSLConnection(t *testing.T) {
	const (
		instance = "instance1"
	)
	tests := []struct {
		name         string
		projectID    string
		expectedFail bool
		expectedSave *sqladmin.DatabaseInstance
	}{

		{
			name:         "require ssl",
			projectID:    "project-exists",
			expectedFail: false,
			expectedSave: &sqladmin.DatabaseInstance{
				Name:    "instance1",
				Project: "project-exists",
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						RequireSsl: true,
					},
				},
			},
		},
		{
			name:         "instance not found",
			projectID:    "not-found",
			expectedFail: true,
			expectedSave: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &stubs.CloudSQL{}
			ctx := context.Background()
			c := NewCloudSQL(s)
			if err := c.RequireSSL(ctx, tt.projectID, instance); err != nil && !tt.expectedFail {
				t.Errorf("%q failed: %q", tt.name, err)
			}

			if diff := cmp.Diff(s.SavedInstanceUpdated, tt.expectedSave); !tt.expectedFail && diff != "" {
				t.Errorf("%v failed diff: %+v", tt.name, diff)
			}
		})
	}
}

func TestClosePublicAccess(t *testing.T) {
	const (
		instance  = "instance-name"
		projectID = "project1"
	)
	tests := []struct {
		name     string
		acls     []*sqladmin.AclEntry
		expected *sqladmin.DatabaseInstance
	}{
		{
			name: "close public access in a existing database with only one auth ip",
			expected: &sqladmin.DatabaseInstance{
				Name:    instance,
				Project: projectID,
				Settings: &sqladmin.Settings{
					IpConfiguration: &sqladmin.IpConfiguration{
						AuthorizedNetworks: nil,
						NullFields:         []string{"AuthorizedNetworks"},
					},
				},
			},
			acls: []*sqladmin.AclEntry{{Value: "0.0.0.0/0"}},
		},
		{
			name: "close public access in a existing database with more than one auth ip",
			acls: []*sqladmin.AclEntry{
				{Value: "0.0.0.0/0"},
				{Value: "199.27.199.0/24"},
			},
			expected: &sqladmin.DatabaseInstance{
				Name:    instance,
				Project: projectID,
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cloudSQLStub := &stubs.CloudSQL{}
			ctx := context.Background()
			c := NewCloudSQL(cloudSQLStub)
			if err := c.ClosePublicAccess(ctx, projectID, instance, tt.acls); err != nil && tt.expected != nil {
				t.Errorf("%v failed: %q", tt.name, err)
			}
			if diff := cmp.Diff(cloudSQLStub.SavedInstanceUpdated, tt.expected); diff != "" {
				t.Errorf("%v failed difference:%+v", tt.name, diff)
			}
		})
	}
}
