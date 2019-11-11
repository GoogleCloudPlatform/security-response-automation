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
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
)

// ComputeClient contains minimum interface required by the host service.
type ComputeClient interface {
	DiskInsert(context.Context, string, string, *compute.Disk) (*compute.Operation, error)
	CreateSnapshot(context.Context, string, string, string, *compute.Snapshot) (*compute.Operation, error)
	DeleteAccessConfig(ctx context.Context, project, zone, instance, accessConfig, networkInterface string) (*compute.Operation, error)
	DeleteDiskSnapshot(context.Context, string, string) (*compute.Operation, error)
	DeleteInstance(context.Context, string, string, string) (*compute.Operation, error)
	GetInstance(ctx context.Context, project, zone, instance string) (*compute.Instance, error)
	ListDisks(context.Context, string, string) (*compute.DiskList, error)
	ListProjectSnapshots(context.Context, string) (*compute.SnapshotList, error)
	SetLabels(context.Context, string, string, *compute.GlobalSetLabelsRequest) (*compute.Operation, error)
	StartInstance(context.Context, string, string, string) (*compute.Operation, error)
	StopInstance(context.Context, string, string, string) (*compute.Operation, error)
	WaitGlobal(string, *compute.Operation) []error
	WaitZone(string, string, *compute.Operation) []error
}

// Host service.
type Host struct {
	client ComputeClient
}

// NewHost returns a host service.
func NewHost(cs ComputeClient) *Host {
	return &Host{client: cs}
}

// DeleteDiskSnapshot deletes the given snapshot from the project.
func (h *Host) DeleteDiskSnapshot(ctx context.Context, projectID, snapshot string) error {
	op, err := h.client.DeleteDiskSnapshot(ctx, projectID, snapshot)
	if err != nil {
		return nil
	}
	if errs := h.WaitGlobal(projectID, op); len(errs) > 0 {
		return errors.Wrap(errs[0], "failed waiting")
	}
	return nil
}

// RemoveExternalIPs iterates on all network interfaces of an instance and deletes its accessConfigs, actually removing the external IP addresses of the instance.
func (h *Host) RemoveExternalIPs(ctx context.Context, project, zone, instance string) error {
	i, err := h.client.GetInstance(ctx, project, zone, instance)
	if err != nil {
		return fmt.Errorf("failed to get instance: %q", err)
	}

	for _, ni := range i.NetworkInterfaces {
		for _, ac := range ni.AccessConfigs {
			if ac.Type != "ONE_TO_ONE_NAT" {
				continue
			}

			op, err := h.client.DeleteAccessConfig(ctx, project, zone, instance, ac.Name, ni.Name)
			if err != nil {
				return fmt.Errorf("failed to remove external ip: %q", err)
			}
			if errs := h.WaitZone(project, zone, op); len(errs) > 0 {
				return fmt.Errorf("failed to waiting instance. Errors[0]: %s", errs[0])
			}
		}
	}

	return nil
}

// DiskSnapshot gets a snapshot by name associated with a given disk.
func (h *Host) DiskSnapshot(ctx context.Context, snapshotName, projectID string, disk *compute.Disk) (*compute.Snapshot, error) {
	snapshots, err := h.ListProjectSnapshots(ctx, projectID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list snapshots")
	}
	for _, s := range snapshots.Items {
		if s.SourceDisk == disk.SelfLink && s.Name == snapshotName {
			return s, nil
		}
	}
	return nil, errors.New("failed to find snapshot")
}

// CreateDiskSnapshot creates a snapshot.
func (h *Host) CreateDiskSnapshot(ctx context.Context, projectID, zone, disk, name string) error {
	op, err := h.client.CreateSnapshot(ctx, projectID, zone, disk, &compute.Snapshot{
		Description:       "Snapshot of " + disk,
		Name:              name,
		CreationTimestamp: time.Now().Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %q", err)
	}
	if errs := h.WaitZone(projectID, zone, op); len(errs) > 0 {
		return errors.Wrap(errs[0], "failed waiting: first error")
	}
	return nil
}

// CopyDiskSnapshot creates a disk from a snapshot and moves it to another project.
func (h *Host) CopyDiskSnapshot(ctx context.Context, srcProjectID, dstProjectID, zone, name string) error {
	op, err := h.client.DiskInsert(ctx, dstProjectID, zone, &compute.Disk{
		Name:           fmt.Sprintf("%s-%d", name, time.Now().Unix()),
		SourceSnapshot: fmt.Sprintf("projects/%s/global/snapshots/%s", srcProjectID, name),
	})
	if err != nil {
		return fmt.Errorf("failed to copy snapshot: %q", err)
	}
	if errs := h.WaitZone(dstProjectID, zone, op); len(errs) > 0 {
		return errors.Wrap(errs[0], "failed waiting: first error")
	}
	return nil
}

// ListProjectSnapshots returns a list of snapshots.
func (h *Host) ListProjectSnapshots(ctx context.Context, projectID string) (*compute.SnapshotList, error) {
	return h.client.ListProjectSnapshots(ctx, projectID)
}

// ListInstanceDisks returns a list of disk names for a given instance.
func (h *Host) ListInstanceDisks(ctx context.Context, projectID, zone, instance string) ([]*compute.Disk, error) {
	ds, err := h.client.ListDisks(ctx, projectID, zone)
	if err != nil {
		return nil, fmt.Errorf("failed to list disks: %q", err)
	}
	dl := []*compute.Disk{}
	for _, d := range ds.Items {
		if h.diskBelongsToInstance(d, instance) {
			dl = append(dl, d)
		}
	}
	log.Printf("got %d disks associated with instance %q", len(dl), instance)
	return dl, nil
}

// SetSnapshotLabels sets the labels on a snapshot.
func (h *Host) SetSnapshotLabels(ctx context.Context, projectID, snapshotName string, disk *compute.Disk, labels map[string]string) error {
	log.Printf("get snapshot %q from %q %q", snapshotName, projectID, disk.Name)
	snapshot, err := h.DiskSnapshot(ctx, snapshotName, projectID, disk)
	if err != nil {
		return errors.Wrapf(err, "failed to get disk snapshots for %s in %s", disk.Name, projectID)
	}
	id := strconv.FormatUint(snapshot.Id, 10)
	labelFp := snapshot.LabelFingerprint

	req := &compute.GlobalSetLabelsRequest{LabelFingerprint: labelFp, Labels: labels}
	log.Printf("set label for %q %+v", projectID, labels)
	op, err := h.client.SetLabels(ctx, projectID, id, req)
	if err != nil {
		return errors.Wrapf(err, "failed setting labels for %s %s", projectID, id)
	}
	if errs := h.WaitGlobal(projectID, op); len(errs) > 0 {
		return errors.Wrapf(errs[0], "failed waiting for setting labels on %s", projectID)
	}
	return nil
}

// WaitZone will wait for the zonal operation to complete.
func (h *Host) WaitZone(project, zone string, op *compute.Operation) []error {
	return h.client.WaitZone(project, zone, op)
}

// WaitGlobal will wait for the global operation to complete.
func (h *Host) WaitGlobal(project string, op *compute.Operation) []error {
	return h.client.WaitGlobal(project, op)
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

// StopInstance stops the provided instance.
func (h *Host) StopInstance(ctx context.Context, projectID, zone, instance string) error {
	op, err := h.client.StopInstance(ctx, projectID, zone, instance)
	if err != nil {
		return fmt.Errorf("failed to stop instance: %q", err)
	}
	if errs := h.WaitZone(projectID, zone, op); len(errs) > 0 {
		return fmt.Errorf("failed to waiting instance. Errors[0]: %s", errs[0])
	}
	return nil
}

// StartInstance starts a given instance in given zone.
func (h *Host) StartInstance(ctx context.Context, projectID, zone, instance string) error {
	op, err := h.client.StartInstance(ctx, projectID, zone, instance)
	if err != nil {
		return fmt.Errorf("failed to start instance: %q", err)
	}
	if errs := h.WaitZone(projectID, zone, op); len(errs) > 0 {
		return fmt.Errorf("failed to waiting instance. Errors[0]: %s", errs[0])
	}
	return nil
}

// DeleteInstance starts a given instance in given zone.
func (h *Host) DeleteInstance(ctx context.Context, projectID, zone, instance string) (*compute.Operation, error) {
	return h.client.DeleteInstance(ctx, projectID, zone, instance)
}
