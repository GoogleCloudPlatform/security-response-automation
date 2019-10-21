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
	"encoding/json"
	"log"
	"strings"
	"time"

	pb "github.com/googlecloudplatform/threat-automation/compiled/etd/protos"
	"github.com/googlecloudplatform/threat-automation/entities"
	"github.com/googlecloudplatform/threat-automation/providers/etd"
	"github.com/pkg/errors"
	compute "google.golang.org/api/compute/v1"
)

const (
	snapshotPrefix = "forensic-snapshots-"
	// allowSnapshotOlderThanDuration defines how old a snapshot must be before we overwrite.
	allowSnapshotOlderThanDuration = 5 * time.Minute
	// maxLabelLength is the maximum size of a label name.
	maxLabelLength = 60
)

// Required contains the required values needed for this function.
type Required struct {
	ProjectID, RuleName, Instance, Zone string
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Required, error) {
	var finding pb.BadIP
	r := &Required{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(entities.ErrUnmarshal, err.Error())
	}
	// TODO: Support pb.BadDomain as well.
	switch finding.GetJsonPayload().GetDetectionCategory().GetRuleName() {
	case "bad_ip":
		r.ProjectID = finding.GetJsonPayload().GetProperties().GetProjectId()
		r.RuleName = finding.GetJsonPayload().GetDetectionCategory().GetRuleName()
		r.Instance = etd.Instance(finding.GetJsonPayload().GetProperties().GetInstanceDetails())
		r.Zone = finding.GetJsonPayload().GetProperties().GetZone()
	}
	if r.RuleName == "" || r.ProjectID == "" || r.Instance == "" || r.Zone == "" {
		return nil, entities.ErrValueNotFound
	}
	return r, nil
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
func Execute(ctx context.Context, required *Required, ent *entities.Entity) error {
	log.Printf("listing disk names within instance %q, in zone %q and project %q", required.Instance, required.Zone, required.ProjectID)

	rule := strings.Replace(required.RuleName, "_", "-", -1)
	disks, err := ent.Host.ListInstanceDisks(ctx, required.ProjectID, required.Zone, required.Instance)
	if err != nil {
		return errors.Wrap(err, "failed to list disks")
	}

	log.Printf("listing snapshots in project %q", required.ProjectID)

	snapshots, err := ent.Host.ListProjectSnapshots(ctx, required.ProjectID)
	if err != nil {
		return errors.Wrap(err, "failed to list snapshots")
	}

	log.Printf("obtained the following list of snapshots in project %q: %+v", required.Instance, snapshots.Items)

	for _, disk := range disks {
		sn := snapshotName(rule, disk.Name)
		create, removeExisting, err := canCreateSnapshot(snapshots, disk, rule)
		if err != nil {
			return err
		}
		log.Printf("disk %q returned %v as can be deleted", required.Instance, create)

		if !create {
			continue
		}

		if err := removeExistingSnapshots(ent.Host, required.ProjectID, removeExisting); err != nil {
			return err
		}
		ent.Logger.Info("removed existing snapshot for disk %s", disk.Name)

		if err := createSnapshot(ctx, ent.Host, disk, required.ProjectID, required.Zone, sn); err != nil {
			return err
		}
		ent.Logger.Info("created snapshot for disk %s", disk.Name)
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
func createSnapshot(ctx context.Context, h *entities.Host, disk *compute.Disk, projectID, zone, name string) error {
	op, err := h.CreateDiskSnapshot(ctx, projectID, zone, disk.Name, name)
	if err != nil {
		return errors.Wrap(err, "failed to create disk snapshot")
	}
	if errs := h.WaitZone(projectID, zone, op); len(errs) > 0 {
		return errors.Wrap(errs[0], "failed waiting: first error")
	}
	return nil
}

func removeExistingSnapshots(h *entities.Host, projectID string, remove map[string]bool) error {
	for k := range remove {
		op, err := h.DeleteDiskSnapshot(projectID, k)
		if err != nil {
			return err
		}
		if errs := h.WaitGlobal(projectID, op); len(errs) > 0 {
			return errors.Wrap(errs[0], "failed waiting: first error")
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
