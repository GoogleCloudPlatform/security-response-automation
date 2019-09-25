package cloudfunctions

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

	"cloud.google.com/go/pubsub"
	compute "google.golang.org/api/compute/v1"

	"github.com/googlecloudplatform/threat-automation/entities"
)

const (
	snapshotPrefix = "forensic-snapshots-"
	// allowSnapshotOlderThanDuration defines how old a snapshot must be before we overwrite.
	allowSnapshotOlderThanDuration = 5 * time.Minute
	// maxLabelLength is the maximum size of a label name.
	maxLabelLength = 60
)

// supportedRules contains a map of rules this function supports.
var supportedRules = map[string]bool{"bad_ip": true, "bad_domain": true}

// CreateSnapshot creates a snapshot of an instance's disk.
//
// For a given supported finding pull each disk associated with the affected instance.
// 	- Check to make sure we haven't created a snapshot for this finding recently.
// 	- Create a new snapshot for each disk labeled with the finding and current time.
//
// In order for the snapshot to be create the service account must be granted the correct
// role on the affected project. At this time this grant is defined per project but should
// be changed to support folder and organization level grants.
func CreateSnapshot(ctx context.Context, m pubsub.Message, r *entities.Resource, h *entities.Host) error {
	f := entities.NewFinding()

	if err := f.ReadFinding(&m); err != nil {
		return fmt.Errorf("failed to read finding: %q", err)
	}

	if !supportedRules[f.RuleName()] {
		return nil
	}

	rule := strings.Replace(f.RuleName(), "_", "-", -1)
	disks, err := h.ListInstanceDisks(ctx, f.ProjectID(), f.Zone(), f.Instance())
	if err != nil {
		return fmt.Errorf("failed to list disks: %q", err)
	}
	snapshots, err := h.ListProjectSnapshots(ctx, f.ProjectID())
	if err != nil {
		return fmt.Errorf("failed to list snapshots: %q", err)
	}

	for _, disk := range disks {
		sn := snapshotName(rule, disk.Name)

		create, removeExisting, err := canCreateSnapshot(snapshots, disk, rule)
		if err != nil {
			return err
		}

		if !create {
			continue
		}

		if err := removeExistingSnapshots(h, f, removeExisting); err != nil {
			return err
		}

		if err := createSnapshot(ctx, h, f, disk, sn); err != nil {
			return err
		}
		// TODO(tomfitzgerald): Add metadata (indicators) to snapshot labels.
	}
	return nil
}

// canCreateSnapshot checks if we should create a snapshot along with a map of existing snapshots to be removed.
func canCreateSnapshot(snapshots *compute.SnapshotList, disk *compute.Disk, rule string) (bool, map[string]bool, error) {
	create := true
	prefix := snapshotName(rule, disk.Name)
	removeExisting := map[string]bool{}
	for _, s := range snapshots.Items {
		if s.SourceDisk != disk.SelfLink || !strings.HasPrefix(s.Name, prefix) {
			continue
		}
		isNew, err := isSnapshotCreatedWithin(s.CreationTimestamp, allowSnapshotOlderThanDuration)
		if err != nil {
			return false, nil, err
		}
		if isNew {
			create = !isNew
			break
		}
		removeExisting[s.Name] = true
	}
	return create, removeExisting, nil
}

// createSnaphot will create the snapshot and wait for its completion.
func createSnapshot(ctx context.Context, h *entities.Host, f *entities.Finding, disk *compute.Disk, name string) error {
	op, err := h.CreateDiskSnapshot(ctx, f.ProjectID(), f.Zone(), disk.Name, name)
	if err != nil {
		return fmt.Errorf("failed to create disk snapshot: %q", err)
	}
	if errs := h.WaitZone(f.ProjectID(), f.Zone(), op); len(errs) > 0 {
		return fmt.Errorf("failed waiting: first error: %s", errs[0])
	}
	return nil
}

func removeExistingSnapshots(h *entities.Host, f *entities.Finding, remove map[string]bool) error {
	for k := range remove {
		op, err := h.DeleteDiskSnapshot(f.ProjectID(), k)
		if err != nil {
			return err
		}
		if errs := h.WaitGlobal(f.ProjectID(), op); len(errs) > 0 {
			return fmt.Errorf("failed waiting")
		}
	}
	return nil
}

// isSnapshotCreatedWithin checks if the previous snapshots created recently.
func isSnapshotCreatedWithin(snapshotTime string, window time.Duration) (bool, error) {
	t, err := time.Parse(time.RFC3339, snapshotTime)
	if err != nil {
		return false, err
	}
	return time.Since(t) < window, nil
}

func snapshotName(rule, disk string) string {
	return snapshotPrefix + rule + "-" + disk
}
