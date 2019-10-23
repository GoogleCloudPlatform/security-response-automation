package stubs

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

// ContainerStub provides a stub for the Container client.
type ContainerStub struct {
	UpdatedAddonsConfig *container.SetAddonsConfigRequest
}

// UpdateAddonsConfig updates the addons configuration of a given cluster.
func (c *ContainerStub) UpdateAddonsConfig(ctx context.Context, projectID, zone, clusterID string, conf *container.SetAddonsConfigRequest) (*container.Operation, error) {
	c.UpdatedAddonsConfig = conf
	return &container.Operation{}, nil
}
