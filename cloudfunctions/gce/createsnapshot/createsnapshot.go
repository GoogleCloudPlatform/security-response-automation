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
	"github.com/googlecloudplatform/threat-automation/providers/etd"
	"github.com/googlecloudplatform/threat-automation/services"
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
	ProjectID, RuleName, Instance, Zone string
}

// Services contains the services needed for this function.
type Services struct {
	Host   *services.Host
	Logger *services.Logger
}

// ReadFinding will attempt to deserialize all supported findings for this function.
func ReadFinding(b []byte) (*Values, error) {
	var finding pb.BadIP
	r := &Values{}
	if err := json.Unmarshal(b, &finding); err != nil {
		return nil, errors.Wrap(services.ErrUnmarshal, err.Error())
	}
	// TODO: Support pb.BadDomain as well.
	switch finding.GetJsonPayload().GetDetectionCategory().GetRuleName() {
	case "bad_ip":
		r.ProjectID = finding.GetJsonPayload().GetProperties().GetProjectId()
		r.RuleName = finding.GetJsonPayload().GetDetectionCategory().GetRuleName()
		r.Instance = etd.Instance(finding.GetJsonPayload().GetProperties().GetInstanceDetails())
		r.Zone = etd.Zone(finding.GetJsonPayload().GetProperties().GetInstanceDetails())
	default:
		return nil, services.ErrUnsupportedFinding
	}
	if r.RuleName == "" || r.ProjectID == "" || r.Instance == "" || r.Zone == "" {
		return nil, services.ErrValueNotFound
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
func Execute(ctx context.Context, values *Values, services *Services) error {
	log.Printf("listing disk names within instance %q, in zone %q and project %q", values.Instance, values.Zone, values.ProjectID)

	rule := strings.Replace(values.RuleName, "_", "-", -1)
	disks, err := services.Host.ListInstanceDisks(ctx, values.ProjectID, values.Zone, values.Instance)
	if err != nil {
		return errors.Wrap(err, "failed to list disks")
	}

	snapshots, err := services.Host.ListProjectSnapshots(ctx, values.ProjectID)
	if err != nil {
		return errors.Wrap(err, "failed to list snapshots")
	}
	log.Printf("got %d existing snapshots for project %q", len(snapshots.Items), values.ProjectID)

	for _, disk := range disks {
		snapshotName := createSnapshotName(rule, disk.Name)
		create, removeExisting, err := canCreateSnapshot(snapshots, disk, rule)
		if err != nil {
			return errors.Wrapf(err, "failed checking if can create snapshot for %q", disk.Name)
		}

		if !create {
			log.Printf("snapshot %q for disk %q will be skipped (not old enough or from another finding)", snapshotName, disk.Name)
			continue
		}

		for k := range removeExisting {
			if err := services.Host.DeleteDiskSnapshot(ctx, values.ProjectID, k); err != nil {
				return errors.Wrapf(err, "failed deleting snapshot: %q", k)
			}
			services.Logger.Info("removed existing snapshot %q from disk %q", k, disk.Name)
		}

		if err := services.Host.CreateDiskSnapshot(ctx, values.ProjectID, values.Zone, disk.Name, snapshotName); err != nil {
			return errors.Wrapf(err, "failed creating snapshot: %q", snapshotName)
		}
		services.Logger.Info("created snapshot for disk %q", disk.Name)

		if err := services.Host.SetSnapshotLabels(ctx, values.ProjectID, snapshotName, disk, labels); err != nil {
			return errors.Wrapf(err, "failed setting labels: %q", snapshotName)
		}
		log.Printf("set labels for snapshot %q for disk %q", snapshotName, disk.Name)
	}
	log.Printf("completed")
	return nil
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
