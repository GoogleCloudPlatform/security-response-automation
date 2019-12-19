package disabledashboard

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
	"google.golang.org/api/container/v1"
)

func TestDisableDashboard(t *testing.T) {
	ctx := context.Background()

	test := []struct {
		name            string
		expectedRequest *container.SetAddonsConfigRequest
	}{
		{
			name: "disable dashboard",
			expectedRequest: &container.SetAddonsConfigRequest{
				AddonsConfig: &container.AddonsConfig{
					KubernetesDashboard: &container.KubernetesDashboard{
						Disabled: true,
					},
				},
			},
		},
	}
	for _, tt := range test {
		svcs, contStub := disableDashboardSetup()
		values := &Values{
			ProjectID: "project-test",
			Zone:      "us-central1-a",
			ClusterID: "test-cluster",
		}
		if err := Execute(ctx, values, &Services{
			Container: svcs.Container,
			Resource:  svcs.Resource,
			Logger:    svcs.Logger,
		}); err != nil {
			t.Errorf("%s test failed want:%q", tt.name, err)
		}
		if diff := cmp.Diff(contStub.UpdatedAddonsConfig, tt.expectedRequest); diff != "" {
			t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedRequest, contStub.UpdatedAddonsConfig)
		}
	}
}

func disableDashboardSetup() (*services.Global, *stubs.ContainerStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	contStub := &stubs.ContainerStub{}
	cont := services.NewContainer(contStub)
	crmStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	resource := services.NewResource(crmStub, storageStub)
	return &services.Global{Logger: log, Resource: resource, Container: cont}, contStub
}
