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
	"log"
	"time"

	compute "google.golang.org/api/compute/v1"
)

const (
	// Maximum number of loops (where each loop is defined below) to wait.
	maxLoops = 180
	// How many seconds to poll each loop to check if the operation has completed.
	loopSleep = 5 * time.Second
)

// Compute client.
type Compute struct {
	compute   *compute.Service
	disks     *compute.DisksService
	snapshots *compute.SnapshotsService
	opsZone   *compute.ZoneOperationsService
	opsGlobal *compute.GlobalOperationsService
}

// NewCompute returns and initializes a Compute client.
func NewCompute(ctx context.Context) (*Compute, error) {
	cc, err := compute.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to init cs: %q", err)
	}
	return &Compute{
		compute:   cc,
		disks:     compute.NewDisksService(cc),
		snapshots: compute.NewSnapshotsService(cc),
		opsZone:   compute.NewZoneOperationsService(cc),
		opsGlobal: compute.NewGlobalOperationsService(cc),
	}, nil
}

// DiskInsert creates a new disk in the project.
func (c *Compute) DiskInsert(ctx context.Context, projectID, zone string, disk *compute.Disk) (*compute.Operation, error) {
	return c.disks.Insert(projectID, zone, disk).Context(ctx).Do()
}

// DeleteDiskSnapshot deletes the given snapshot from the project.
func (c *Compute) DeleteDiskSnapshot(ctx context.Context, project, snapshot string) (*compute.Operation, error) {
	return c.snapshots.Delete(project, snapshot).Context(ctx).Do()
}

// InsertFirewallRule inserts a new firewall rule.
func (c *Compute) InsertFirewallRule(ctx context.Context, projectID string, fw *compute.Firewall) (*compute.Operation, error) {
	return c.compute.Firewalls.Insert(projectID, fw).Context(ctx).Do()
}

// PatchFirewallRule updates the firewall rule for the given project.
func (c *Compute) PatchFirewallRule(ctx context.Context, projectID string, rule string, rb *compute.Firewall) (*compute.Operation, error) {
	return c.compute.Firewalls.Patch(projectID, rule, rb).Context(ctx).Do()
}

// DeleteFirewallRule deletes the firewall rule for the given project.
func (c *Compute) DeleteFirewallRule(ctx context.Context, projectID string, rule string) (*compute.Operation, error) {
	return c.compute.Firewalls.Delete(projectID, rule).Context(ctx).Do()
}

// GetInstance returns the specified compute instance resource.
func (c *Compute) GetInstance(ctx context.Context, project, zone, instance string) (*compute.Instance, error) {
	return c.compute.Instances.Get(project, zone, instance).Context(ctx).Do()
}

// DeleteAccessConfig deletes an access config from an instance's network interface.
func (c *Compute) DeleteAccessConfig(ctx context.Context, project, zone, instance, accessConfig, networkInterface string) (*compute.Operation, error) {
	return c.compute.Instances.DeleteAccessConfig(project, zone, instance, accessConfig, networkInterface).Context(ctx).Do()
}

// FirewallRule get the details of a firewall rule
func (c *Compute) FirewallRule(ctx context.Context, projectID string, ruleID string) (*compute.Firewall, error) {
	return c.compute.Firewalls.Get(projectID, ruleID).Context(ctx).Do()
}

// CreateSnapshot creates a snapshot of a specified persistent disk.
func (c *Compute) CreateSnapshot(ctx context.Context, projectID, zone, disk string, rb *compute.Snapshot) (*compute.Operation, error) {
	return c.compute.Disks.CreateSnapshot(projectID, zone, disk, rb).Context(ctx).Do()
}

// ListDisks returns a list of disk for a given project.
func (c *Compute) ListDisks(ctx context.Context, projectID, zone string) (*compute.DiskList, error) {
	return c.compute.Disks.List(projectID, zone).Context(ctx).Do()
}

// ListProjectSnapshots returns a list of snapshot reousrces for a given project.
func (c *Compute) ListProjectSnapshots(ctx context.Context, projectID string) (*compute.SnapshotList, error) {
	return c.compute.Snapshots.List(projectID).Context(ctx).Do()
}

// SetLabels sets labels on a snapshot.
func (c *Compute) SetLabels(ctx context.Context, projectID, resource string, rb *compute.GlobalSetLabelsRequest) (*compute.Operation, error) {
	return c.compute.Snapshots.SetLabels(projectID, resource, rb).Context(ctx).Do()
}

// WaitZone will wait for the zonal operation to complete.
func (c *Compute) WaitZone(project, zone string, op *compute.Operation) []error {
	return wait(op, func() (*compute.Operation, error) {
		return c.opsZone.Get(project, zone, fmt.Sprintf("%d", op.Id)).Do()
	})
}

// WaitGlobal will wait for the global operation to complete.
func (c *Compute) WaitGlobal(project string, op *compute.Operation) []error {
	return wait(op, func() (*compute.Operation, error) {
		return c.opsGlobal.Get(project, fmt.Sprintf("%d", op.Id)).Do()
	})
}

// StopInstance instance command to some instance/zone
func (c *Compute) StopInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return c.compute.Instances.Stop(projectID, zone, instance).Context(ctx).Do()
}

// StartInstance starts a given instance in given zone.
func (c *Compute) StartInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return c.compute.Instances.Start(projectID, zone, instance).Context(ctx).Do()
}

// DeleteInstance deletes a given instance in given zone.
func (c *Compute) DeleteInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return c.compute.Instances.Delete(projectID, zone, instance).Context(ctx).Do()
}

func wait(op *compute.Operation, fn func() (*compute.Operation, error)) []error {
	if op.Error != nil {
		return returnErrorCodes(op.Error.Errors)
	}
	for i := 0; i < maxLoops; i++ {
		o, err := fn()
		if err != nil {
			return []error{err}
		}
		if o.Error != nil {
			return returnErrorCodes(o.Error.Errors)
		}
		if o.Status == "DONE" {
			return nil
		}
		if i%4 == 0 {
			log.Println("waiting")
		}
		time.Sleep(loopSleep)
	}
	return []error{fmt.Errorf("operation timed out: %q", op.Name)}
}

func returnErrorCodes(errors []*compute.OperationErrorErrors) []error {
	out := []error{}
	for _, err := range errors {
		out = append(out, fmt.Errorf("fail: %q", err.Code))
	}
	return out
}
