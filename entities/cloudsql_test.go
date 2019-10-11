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
	const (
		instance  = "instance1"
		projectID = "project1"
		region    = "us-central1"
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
				Name:           "instance1",
				Project:        "project-exists",
				ConnectionName: "project-exists" + ":" + "us-central1" + ":" + "instance1",
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
			_, err := c.RequireSSL(ctx, tt.projectID, instance, region)
			if err != nil && !tt.expectedFail {
				t.Errorf("%q failed: %q", tt.name, err)
			}

			if diff := cmp.Diff(s.SavedInstanceUpdated, tt.expectedSave); !tt.expectedFail && diff != "" {
				t.Errorf("%v failed diff: %+v", tt.name, diff)
			}
		})
	}
}
