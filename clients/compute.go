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
	"fmt"

	cs "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
)

// ComputeService is the interface used by CS.
type ComputeService interface {
	PatchFirewallRule(string, string, *cs.Firewall) (*cs.Operation, error)
	CreateSnapshot(string, string, string, *cs.Snapshot) (*cs.Operation, error)
	ListProjectSnapshots(string) (*cs.SnapshotList, error)
	ListDisks(string, string) (*cs.DiskList, error)
	SetLabels(string, string, *cs.GlobalSetLabelsRequest) (*cs.Operation, error)
}

// InstantiateCompute instantiates a compute service.
func InstantiateCompute(c *Client) error {
	cc, err := cs.NewService(c.ctx, option.WithCredentialsFile(authFile))
	if err != nil {
		return fmt.Errorf("failed to init cs: %q", err)
	}
	c.cs = cc
	c.sss = cs.NewSnapshotsService(c.cs)
	return nil
}

// PatchFirewallRule updates the firewall rule for the given project.
func (c *Client) PatchFirewallRule(projectID string, firewallrule string, rb *cs.Firewall) (*cs.Operation, error) {
	return c.cs.Firewalls.Patch(projectID, firewallrule, rb).Context(c.ctx).Do()
}

// CreateSnapshot creates a snapshot of a specified persistent disk.
func (c *Client) CreateSnapshot(projectID string, zone string, disk string, rb *cs.Snapshot) (*cs.Operation, error) {
	return c.cs.Disks.CreateSnapshot(projectID, zone, disk, rb).Context(c.ctx).Do()
}

// ListDisks returns a list of disk names for a given project.
func (c *Client) ListDisks(projectID, zone string) (*cs.DiskList, error) {
	return c.cs.Disks.List(projectID, zone).Context(c.ctx).Do()
}

// ListProjectSnapshots returns a list of snapshot reousrces for a given project.
func (c *Client) ListProjectSnapshots(projectID string) (*cs.SnapshotList, error) {
	return c.cs.Snapshots.List(projectID).Context(c.ctx).Do()
}

// SetLabels sets the labels on a snapshot.
func (c *Client) SetLabels(projectID, resource string, rb *cs.GlobalSetLabelsRequest) (*cs.Operation, error) {
	return c.cs.Snapshots.SetLabels(projectID, resource, rb).Context(c.ctx).Do()
}
