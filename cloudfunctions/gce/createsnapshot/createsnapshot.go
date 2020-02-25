package createsnapshot

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
	"strings"
	"time"

	"github.com/googlecloudplatform/security-response-automation/services"
	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
)

const (
	snapshotPrefix = "forensic-snapshots-"
	// allowSnapshotOlderThanDuration defines how old a snapshot must be before we overwrite.
	allowSnapshotOlderThanDuration = 5 * time.Minute
)

// labels to be saved with each disk snapshot created.
var labels = map[string]string{
	"info": "created-by-security-response-automation",
}

// Values contains the required values needed for this function.
type Values struct {
	DryRun    bool
	ProjectID string
	RuleName  string
	Instance  string
	Zone      string
	Output    []string

	Turbinia struct {
		ProjectID string
		Topic     string
		Zone      string
	}

	// DestProjectID is the optional project ID where the newly created snapshot should be copied to.
	DestProjectID string
	// DestZone is the optional zone where the newly created snapshot should be copied to.
	DestZone string
}

// Services contains the services needed for this function.
type Services struct {
	Host     *services.Host
	Logger   *services.Logger
	Resource *services.Resource
}

// Output contains the output of this function.
type Output struct {
	// DiskNames optionally contains the names of the disks copied to a target project.
	DiskNames []string
}

// Execute creates a snapshot of an instance's disk.
//
// For a given supported finding pull each disk associated with the affected instance.
// 	- Check to make sure we haven't created a snapshot for this finding recently.
// 	- Create a new snapshot for each disk labeled with the finding and current time.
//
// In order for the snapshot to be create the service account must be granted the correct
// role on the affected project. At this time this grant is defined per project but should
// be changed to support folder and organization level grants.
func Execute(ctx context.Context, values *Values, services *Services) (*Output, error) {
	var output Output
	log.Printf("listing disk names within instance %q, in zone %q and project %q", values.Instance, values.Zone, values.ProjectID)
	disksCopied := []string{}
	rule := strings.Replace(values.RuleName, "_", "-", -1)
	disks, err := services.Host.ListInstanceDisks(ctx, values.ProjectID, values.Zone, values.Instance)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list disks")
	}

	snapshots, err := services.Host.ListProjectSnapshots(ctx, values.ProjectID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to list snapshots")
	}
	log.Printf("got %d existing snapshots for project %q", len(snapshots.Items), values.ProjectID)

	for _, disk := range disks {
		snapshotName := createSnapshotName(rule, disk.Name)
		create, removeExisting, err := canCreateSnapshot(snapshots, disk, rule)
		if err != nil {
			return nil, errors.Wrapf(err, "failed checking if can create snapshot for %q", disk.Name)
		}

		if !create {
			log.Printf("snapshot %q for disk %q will be skipped (not old enough or from another finding)", snapshotName, disk.Name)
			continue
		}

		if values.DryRun {
			services.Logger.Info("dry_run on, would created a snapshot of %q from %q", disk.Name, values.ProjectID)
			continue
		}

		for k := range removeExisting {
			if err := services.Host.DeleteDiskSnapshot(ctx, values.ProjectID, k); err != nil {
				return nil, errors.Wrapf(err, "failed deleting snapshot: %q", k)
			}
			services.Logger.Info("removed existing snapshot %q from disk %q", k, disk.Name)
		}

		log.Printf("creating a snapshot %q for %q", snapshotName, disk.Name)
		if err := services.Host.CreateDiskSnapshot(ctx, values.ProjectID, values.Zone, disk.Name, snapshotName); err != nil {
			return nil, errors.Wrapf(err, "failed creating snapshot: %q", snapshotName)
		}
		services.Logger.Info("created snapshot for disk %q", disk.Name)

		if err := services.Host.SetSnapshotLabels(ctx, values.ProjectID, snapshotName, disk, labels); err != nil {
			return nil, errors.Wrapf(err, "failed setting labels: %q", snapshotName)
		}
		log.Printf("set labels for snapshot %q for disk %q", snapshotName, disk.Name)

		if values.DestProjectID != "" {
			log.Printf("copying snapshot %q for %q to %q in %q", snapshotName, disk.Name, values.DestProjectID, values.DestZone)
			if err := services.Host.CopyDiskSnapshot(ctx, values.ProjectID, values.DestProjectID, values.DestZone, snapshotName); err != nil {
				return nil, errors.Wrapf(err, "failed to copy disk to %q", values.DestProjectID)
			}
			disksCopied = append(disksCopied, snapshotName)
			services.Logger.Info("copied snapshot %q to %q in %q", snapshotName, values.DestProjectID, values.DestZone)
		}
	}
	log.Printf("completed")
	output.DiskNames = disksCopied
	return &output, nil
}

// canCreateSnapshot checks if we should create a snapshot along with a map of existing snapshots to be removed.
func canCreateSnapshot(snapshots *compute.SnapshotList, disk *compute.Disk, rule string) (bool, map[string]bool, error) {
	create := true
	prefix := createSnapshotName(rule, disk.Name)
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

// isSnapshotCreatedWithin checks if the previous snapshots created recently.
func isSnapshotCreatedWithin(snapshotTime string, window time.Duration) (bool, error) {
	t, err := time.Parse(time.RFC3339, snapshotTime)
	if err != nil {
		return false, err
	}
	return time.Since(t) < window, nil
}

func createSnapshotName(rule, disk string) string {
	return snapshotPrefix + rule + "-" + disk
}
