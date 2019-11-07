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

	container "google.golang.org/api/container/v1"
)

// ContainerClient holds the minimum interface required by the Container service.
type ContainerClient interface {
	UpdateAddonsConfig(context.Context, string, string, string, *container.SetAddonsConfigRequest) (*container.Operation, error)
}

// Container Service.
type Container struct {
	client ContainerClient
}

// NewContainer returns a new Container service.
func NewContainer(client ContainerClient) *Container {
	return &Container{client: client}
}

// DisableDashboard disables the Kubernetes Dashboard for a given cluster.
func (c *Container) DisableDashboard(ctx context.Context, projectID, zone, clusterID string) (*container.Operation, error) {
	req := &container.SetAddonsConfigRequest{
		AddonsConfig: &container.AddonsConfig{
			KubernetesDashboard: &container.KubernetesDashboard{
				Disabled: true,
			},
		},
	}
	return c.client.UpdateAddonsConfig(ctx, projectID, zone, clusterID, req)
}
