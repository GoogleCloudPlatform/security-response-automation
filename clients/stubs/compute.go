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
	"fmt"

	compute "google.golang.org/api/compute/v1"
)

// ErrNonexistentVM is a stub error returned simulating an error in case of VM not found.
var ErrNonexistentVM = fmt.Errorf("googleapi: Error 404: The resource 'projects/test/zones/us-central1-a/instances/nonexistent' was not found, notFound")

// ComputeStub provides a stub for the compute client.
type ComputeStub struct {
	SavedFirewallRule           *compute.Firewall
	SavedCreateSnapshots        map[string]compute.Snapshot
	StubbedListProjectSnapshots *compute.SnapshotList
	StubbedListDisks            *compute.DiskList
	StubbedStopInstance         *compute.Operation
	StubbedStartInstance        *compute.Operation
}

// PatchFirewallRule updates the firewall rule for the given project.
func (c *ComputeStub) PatchFirewallRule(_, _ string, rb *compute.Firewall) (*compute.Operation, error) {
	c.SavedFirewallRule = rb

	return nil, nil
}

// CreateSnapshot creates a snapshot of a specified persistent disk.
func (c *ComputeStub) CreateSnapshot(ctx context.Context, _, _, disk string, rb *compute.Snapshot) (*compute.Operation, error) {
	c.SavedCreateSnapshots[disk] = *rb
	return nil, nil
}

// DeleteDiskSnapshot deletes a snapshot.
func (c *ComputeStub) DeleteDiskSnapshot(_, _ string) (*compute.Operation, error) {
	return nil, nil
}

// ListProjectSnapshots returns a list of snapshot resources.
func (c *ComputeStub) ListProjectSnapshots(context.Context, string) (*compute.SnapshotList, error) {
	return c.StubbedListProjectSnapshots, nil
}

// ListDisks returns a list of disks.
func (c *ComputeStub) ListDisks(ctx context.Context, _, _ string) (*compute.DiskList, error) {
	return c.StubbedListDisks, nil
}

// SetLabels sets the labels on a snapshot.
func (c *ComputeStub) SetLabels(context.Context, string, string, *compute.GlobalSetLabelsRequest) (*compute.Operation, error) {
	return nil, nil
}

// WaitGlobal waits globally.
func (c *ComputeStub) WaitGlobal(_ string, _ *compute.Operation) []error {
	return []error{}
}

// WaitZone zone waits at the zone level.
func (c *ComputeStub) WaitZone(_, _ string, _ *compute.Operation) []error {
	return []error{}
}

// StopInstance strop instance
func (c *ComputeStub) StopInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return c.StubbedStopInstance, nil
}

// StartInstance starts a given instance in given zone
func (c *ComputeStub) StartInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return c.StubbedStartInstance, nil
}
