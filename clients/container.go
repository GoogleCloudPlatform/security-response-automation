package clients

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

	container "google.golang.org/api/container/v1"
	"google.golang.org/api/option"
)

// Container client.
type Container struct {
	container *container.Service
}

// NewContainer returns and initializes a Container client.
func NewContainer(ctx context.Context, authFile string) (*Container, error) {
	cc, err := container.NewService(ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		return nil, fmt.Errorf("Failed to init container service: %q", err)
	}

	return &Container{
		container: cc,
	}, nil
}

// DisableKubernetesDashboard disables the kubernetes dashboard for a given cluster.
func (c *Container) DisableKubernetesDashboard(ctx context.Context, projectID, zone, clusterID string) (*container.Operation, error) {
	disableKubernetesDashboard := true
	configRequest := initSetAddonsConfigRequest(disableKubernetesDashboard)
	return c.container.Projects.Zones.Clusters.Addons(projectID, zone, clusterID, configRequest).Context(ctx).Do()
}

// newSetAddonsConfigRequest returns a new SetAddonsConfigRequest with a given AddonsConfig.
func newSetAddonsConfigRequest(addonsConfig *container.AddonsConfig) *container.SetAddonsConfigRequest {
	var setAddonsConfigRequest container.SetAddonsConfigRequest
	setAddonsConfigRequest.AddonsConfig = addonsConfig
	return &setAddonsConfigRequest
}

// newAddonsConfig returns a new AddonsConfig with a given KubernetesDashboard.
func newAddonsConfig(kubernetesDashboard *container.KubernetesDashboard) *container.AddonsConfig {
	var addonsConfig container.AddonsConfig
	addonsConfig.KubernetesDashboard = kubernetesDashboard
	return &addonsConfig
}

// newKubernetesDashboard returns a new KubernetesDashboard.
func newKubernetesDashboard(disabled bool) *container.KubernetesDashboard {
	var kubernetesDashboard container.KubernetesDashboard
	kubernetesDashboard.Disabled = disabled
	return &kubernetesDashboard
}

// initSetAddonsConfigRequest initializes SetAddonsConfigRequest used to disable the Kubernetes Dashboard.
func initSetAddonsConfigRequest(disabled bool) *container.SetAddonsConfigRequest {
	kubernetesDashboard := newKubernetesDashboard(disabled)
	addonsConfig := newAddonsConfig(kubernetesDashboard)
	return newSetAddonsConfigRequest(addonsConfig)
}
