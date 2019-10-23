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
	container "google.golang.org/api/container/v1"
)

func TestDisableDashboard(t *testing.T) {
	const (
		projectID = "threat-auto-tests-07102019"
		zone      = "us-central1-a"
	)

	tests := []struct {
		name            string
		clusterID       string
		expectedError   error
		expectedFail    bool
		expectedRequest *container.SetAddonsConfigRequest
	}{
		{
			name:         "disable kubernetes dashboard",
			clusterID:    "test-cluster",
			expectedFail: false,
			expectedRequest: &container.SetAddonsConfigRequest{
				AddonsConfig: &container.AddonsConfig{
					KubernetesDashboard: &container.KubernetesDashboard{
						Disabled: true,
					},
				},
			},
		},
		{
			name:            "disable kubernetes dashboard in a nonexisting cluster",
			clusterID:       "not-found",
			expectedFail:    true,
			expectedRequest: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			gke := &stubs.ContainerStub{}
			g := NewContainer(gke)
			_, err := g.DisableDashboard(ctx, projectID, zone, tt.clusterID)
			if err != nil && !tt.expectedFail {
				t.Errorf("%v failed: %v", tt.name, tt.expectedError)
			}
			diff := cmp.Diff(gke.UpdatedAddonsConfig, tt.expectedRequest)
			if !tt.expectedFail && diff != "" {
				t.Errorf("%v failed, difference: %+v", tt.name, diff)
			}
		})
	}

}
