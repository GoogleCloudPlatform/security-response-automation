package dryrun

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
	"log"

	"github.com/googlecloudplatform/security-response-automation/clients"
	compute "google.golang.org/api/compute/v1"
)

// Compute dry run client.
type Compute struct {
	computeClient       *clients.Compute
	lastSnapShotCreated *compute.Snapshot
}

// NewDryRunCompute returns and initializes a Compute client.
func NewDryRunCompute(original *clients.Compute) (*Compute, error) {
	return &Compute{computeClient: original}, nil
}

// DiskInsert creates a new disk in the project.
func (c *Compute) DiskInsert(ctx context.Context, projectID, zone string, disk *compute.Disk) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'DiskInsert' with params projectID: %q, zone: %q, disk: %+v", projectID, zone, disk)
	return &compute.Operation{}, nil
}

// DeleteDiskSnapshot deletes the given snapshot from the project.
func (c *Compute) DeleteDiskSnapshot(ctx context.Context, project, snapshot string) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'DeleteDiskSnapshot' with params project: %q, snapshot: %q", project, snapshot)
	return &compute.Operation{}, nil
}

// InsertFirewallRule inserts a new firewall rule.
func (c *Compute) InsertFirewallRule(ctx context.Context, projectID string, fw *compute.Firewall) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'InsertFirewallRule' with params projectID: %q, Firewall: %+v", projectID, fw)
	return &compute.Operation{}, nil
}

// PatchFirewallRule updates the firewall rule for the given project.
func (c *Compute) PatchFirewallRule(ctx context.Context, projectID string, rule string, rb *compute.Firewall) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'PatchFirewallRule' with params projectID: %q, rule: %q, Firewall: %+v", projectID, rule, rb)
	return &compute.Operation{}, nil
}

// DeleteFirewallRule deletes the firewall rule for the given project.
func (c *Compute) DeleteFirewallRule(ctx context.Context, projectID string, rule string) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'DeleteFirewallRule' with params projectID: %q, rule: %q", projectID, rule)
	return &compute.Operation{}, nil
}

// GetInstance returns the specified compute instance resource.
func (c *Compute) GetInstance(ctx context.Context, project, zone, instance string) (*compute.Instance, error) {
	return c.computeClient.GetInstance(ctx, project, zone, instance)
}

// DeleteAccessConfig deletes an access config from an instance's network interface.
func (c *Compute) DeleteAccessConfig(ctx context.Context, project, zone, instance, accessConfig, networkInterface string) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'DeleteAccessConfig' with params project: %q, zone: %q, instance: %q, accessConfig: %q, networkInterface: %q", project, zone, instance, accessConfig, networkInterface)
	return &compute.Operation{}, nil
}

// FirewallRule get the details of a firewall rule
func (c *Compute) FirewallRule(ctx context.Context, projectID string, ruleID string) (*compute.Firewall, error) {
	return c.computeClient.FirewallRule(ctx, projectID, ruleID)
}

// CreateSnapshot creates a snapshot of a specified persistent disk.
func (c *Compute) CreateSnapshot(ctx context.Context, projectID, zone, disk string, rb *compute.Snapshot) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'CreateSnapshot' with params projectID: %q, zone: %q, disk: %q, Snapshot: %+v", projectID, zone, disk, rb)
	c.lastSnapShotCreated = &compute.Snapshot{
		SourceDisk:        "https://www.googleapis.com/compute/v1/projects/" + projectID + "/zones/" + zone + "/disks/" + disk,
		Name:              rb.Name,
		Description:       rb.Description,
		CreationTimestamp: rb.CreationTimestamp}
	return &compute.Operation{}, nil
}

// ListDisks returns a list of disk for a given project.
func (c *Compute) ListDisks(ctx context.Context, projectID, zone string) (*compute.DiskList, error) {
	return c.computeClient.ListDisks(ctx, projectID, zone)
}

// ListProjectSnapshots returns a list of snapshot resources for a given project.
func (c *Compute) ListProjectSnapshots(ctx context.Context, projectID string) (*compute.SnapshotList, error) {
	list, e := c.computeClient.ListProjectSnapshots(ctx, projectID)
	if c.lastSnapShotCreated != nil && list != nil {
		list.Items = append(list.Items, c.lastSnapShotCreated)
	}
	return list, e
}

// SetLabels sets labels on a snapshot.
func (c *Compute) SetLabels(ctx context.Context, projectID, resource string, rb *compute.GlobalSetLabelsRequest) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'SetLabels' with params projectID: %q, resource: %q, GlobalSetLabelsRequest: %+v", projectID, resource, rb)
	return &compute.Operation{}, nil
}

// WaitZone will wait for the zonal operation to complete.
func (c *Compute) WaitZone(project, zone string, op *compute.Operation) []error {
	return []error{}
}

// WaitGlobal will wait for the global operation to complete.
func (c *Compute) WaitGlobal(project string, op *compute.Operation) []error {
	return []error{}
}

// StopInstance instance command to some instance/zone
func (c *Compute) StopInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'StopInstance' with params projectID: %q, zone: %q, instance: %q", projectID, zone, instance)
	return &compute.Operation{}, nil
}

// StartInstance starts a given instance in given zone.
func (c *Compute) StartInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'StartInstance' with params projectID: %q, zone: %q, instance: %q", projectID, zone, instance)
	return &compute.Operation{}, nil
}

// DeleteInstance deletes a given instance in given zone.
func (c *Compute) DeleteInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	log.Printf("dry_run on, would call 'DeleteInstance' with projectID: %q, zone: %q, instance: %q", projectID, zone, instance)
	return &compute.Operation{}, nil
}
