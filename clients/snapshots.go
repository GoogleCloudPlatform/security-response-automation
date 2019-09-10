/*
Package clients provides the required clients for taking automated actions.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package clients

import (
	cs "google.golang.org/api/compute/v1"
)

// SnapshotsService is the interface used by SnapshotsService.
type SnapshotsService interface {
	DeleteDiskSnapshot(string, string) (*cs.Operation, error)
}

// InstantiateSnapshots instantiates a operations service.
func InstantiateSnapshots(c *Client) {
	c.sss = cs.NewSnapshotsService(c.cs)
}

// DeleteDiskSnapshot deletes the given snapshot from the project.
func (c *Client) DeleteDiskSnapshot(project, snapshot string) (*cs.Operation, error) {
	return c.sss.Delete(project, snapshot).Do()
}
