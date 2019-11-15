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

	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
)

// ErrNonexistentVM is a stub error returned simulating an error in case of VM not found.
var ErrNonexistentVM = fmt.Errorf("googleapi: Error 404: The resource 'projects/test/zones/us-central1-a/instances/nonexistent' was not found, notFound")

// ComputeStub provides a stub for the compute client.
type ComputeStub struct {
	SavedFirewallRule            *compute.Firewall
	SavedCreateSnapshots         map[string]compute.Snapshot
	DeletedAccessConfigs         []NetworkAccessConfigStub
	DeleteAccessConfigShouldFail bool
	GetInstanceShouldFail        bool
	StubbedListProjectSnapshots  []*compute.SnapshotList
	StubbedListDisks             *compute.DiskList
	StubbedFirewall              *compute.Firewall
	StubbedStopInstance          *compute.Operation
	StubbedStartInstance         *compute.Operation
	StubbedInstance              *compute.Instance
	SavedDiskInsertDst           string
	DiskInsertCalled             bool
}

// DiskInsert creates a new disk in the project.
func (c *ComputeStub) DiskInsert(ctx context.Context, projectID, zone string, disk *compute.Disk) (*compute.Operation, error) {
	c.SavedDiskInsertDst = projectID
	c.DiskInsertCalled = true
	return nil, nil
}

// NetworkAccessConfigStub tracks deleted AccessConfig's per NetworkInterface.
type NetworkAccessConfigStub struct {
	NetworkInterfaceName string
	AccessConfigName     string
}

// InsertFirewallRule inserts a new firewall rule.
func (c *ComputeStub) InsertFirewallRule(ctx context.Context, projectID string, fw *compute.Firewall) (*compute.Operation, error) {
	c.SavedFirewallRule = fw
	return nil, nil
}

// PatchFirewallRule updates the firewall rule for the given project.
func (c *ComputeStub) PatchFirewallRule(ctx context.Context, projectID string, rule string, rb *compute.Firewall) (*compute.Operation, error) {
	c.SavedFirewallRule = rb
	return nil, nil
}

// DeleteFirewallRule deletes the firewall rule for the given project.
func (c *ComputeStub) DeleteFirewallRule(ctx context.Context, projectID string, rule string) (*compute.Operation, error) {
	return nil, nil
}

// FirewallRule get the details of a firewall rule
func (c *ComputeStub) FirewallRule(ctx context.Context, projectID string, ruleID string) (*compute.Firewall, error) {
	return c.StubbedFirewall, nil
}

// GetInstance returns the specified compute instance resource.
func (c *ComputeStub) GetInstance(ctx context.Context, project, zone, instance string) (*compute.Instance, error) {
	if c.GetInstanceShouldFail {
		return nil, errors.New("api call failed")
	}
	return c.StubbedInstance, nil
}

// DeleteAccessConfig deletes an access config from an instance's network interface.
func (c *ComputeStub) DeleteAccessConfig(ctx context.Context, project, zone, instance, accessConfig, networkInterface string) (*compute.Operation, error) {
	if c.DeleteAccessConfigShouldFail {
		return nil, errors.New("api call failed")
	}
	c.DeletedAccessConfigs = append(c.DeletedAccessConfigs, NetworkAccessConfigStub{
		NetworkInterfaceName: networkInterface,
		AccessConfigName:     accessConfig,
	})
	return nil, nil
}

// CreateSnapshot creates a snapshot of a specified persistent disk.
func (c *ComputeStub) CreateSnapshot(ctx context.Context, _, _, disk string, snapshot *compute.Snapshot) (*compute.Operation, error) {
	c.SavedCreateSnapshots[disk] = *snapshot
	return nil, nil
}

// DeleteDiskSnapshot deletes a snapshot.
func (c *ComputeStub) DeleteDiskSnapshot(_ context.Context, _, _ string) (*compute.Operation, error) {
	return nil, nil
}

// ListProjectSnapshots returns a list of snapshot resources.
func (c *ComputeStub) ListProjectSnapshots(context.Context, string) (*compute.SnapshotList, error) {
	if len(c.StubbedListProjectSnapshots) == 0 {
		return nil, nil
	}
	pop := c.StubbedListProjectSnapshots[len(c.StubbedListProjectSnapshots)-1 : len(c.StubbedListProjectSnapshots)][0]
	c.StubbedListProjectSnapshots = c.StubbedListProjectSnapshots[0 : len(c.StubbedListProjectSnapshots)-1]
	if pop == nil {
		return &compute.SnapshotList{Items: []*compute.Snapshot{}}, nil
	}
	return pop, nil
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

// StopInstance stops an instance.
func (c *ComputeStub) StopInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return c.StubbedStopInstance, nil
}

// StartInstance starts a given instance in given zone.
func (c *ComputeStub) StartInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return c.StubbedStartInstance, nil
}

// DeleteInstance starts a given instance in given zone.
func (c *ComputeStub) DeleteInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return nil, nil
}
