package entities

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
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
)

// ComputeClient contains minimum interface required by the host entity.
type ComputeClient interface {
	CreateSnapshot(context.Context, string, string, string, *compute.Snapshot) (*compute.Operation, error)
	ListProjectSnapshots(context.Context, string) (*compute.SnapshotList, error)
	ListDisks(context.Context, string, string) (*compute.DiskList, error)
	SetLabels(context.Context, string, string, *compute.GlobalSetLabelsRequest) (*compute.Operation, error)
	DeleteDiskSnapshot(string, string) (*compute.Operation, error)
	WaitZone(string, string, *compute.Operation) []error
	WaitGlobal(string, *compute.Operation) []error
}

// Host entity.
type Host struct {
	c ComputeClient
}

// NewHost returns a host entity.
func NewHost(cs ComputeClient) *Host {
	return &Host{c: cs}
}

// DeleteDiskSnapshot deletes the given snapshot from the project.
func (h *Host) DeleteDiskSnapshot(project, snapshot string) (*compute.Operation, error) {
	return h.c.DeleteDiskSnapshot(project, snapshot)
}

// CreateDiskSnapshot creates a snapshot.
func (h *Host) CreateDiskSnapshot(ctx context.Context, projectID, zone, disk, name string) (*compute.Operation, error) {
	cs, err := h.c.CreateSnapshot(ctx, projectID, zone, disk, &compute.Snapshot{
		Description:       "Snapshot of " + disk,
		Name:              name,
		CreationTimestamp: time.Now().Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot: %q", err)
	}
	return cs, nil
}

// ListProjectSnapshots returns a list of snapshots.
func (h *Host) ListProjectSnapshots(ctx context.Context, projectID string) (*compute.SnapshotList, error) {
	snapshots, err := h.c.ListProjectSnapshots(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("failed to list snapshots: %q", err)
	}
	return snapshots, nil
}

// ListInstanceDisks returns a list of disk names for a given instance.
func (h *Host) ListInstanceDisks(ctx context.Context, projectID, zone, instance string) ([]*compute.Disk, error) {
	ds, err := h.c.ListDisks(ctx, projectID, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to list disks: %q", err)
	}
	dl := []*compute.Disk{}
	for _, d := range ds.Items {
		if !h.diskBelongsToInstance(d, instance) {
			return []*compute.Disk{}, nil
		}
		dl = append(dl, d)
	}
	return dl, nil
}

// SetSnapshotLabels sets the labels on a snapshot.
func (h *Host) SetSnapshotLabels(ctx context.Context, projectID, name string, m map[string]string) error {
	rb := &compute.GlobalSetLabelsRequest{Labels: m}
	_, err := h.c.SetLabels(ctx, projectID, "42WmSpB8rSM=", rb)
	if err != nil {
		return fmt.Errorf("failed to set disk labels: %q", err)
	}
	return nil
}

// WaitZone will wait for the zonal operation to complete.
func (h *Host) WaitZone(project, zone string, op *compute.Operation) []error {
	return h.c.WaitZone(project, zone, op)
}

// WaitGlobal will wait for the global operation to complete.
func (h *Host) WaitGlobal(project string, op *compute.Operation) []error {
	return h.c.WaitGlobal(project, op)
}

// diskBelongsToInstance returns if the disk is attributed to the given instance.
func (h *Host) diskBelongsToInstance(disks *compute.Disk, instance string) bool {
	for _, u := range disks.Users {
		if strings.HasSuffix(u, "/instances/"+instance) {
			return true
		}
	}
	return false
}
