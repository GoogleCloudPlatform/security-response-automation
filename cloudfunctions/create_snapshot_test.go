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
	"testing"
	"time"

	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"

	"cloud.google.com/go/pubsub"
	"github.com/google/go-cmp/cmp"
	compute "google.golang.org/api/compute/v1"
)

var (
	sampleFinding = pubsub.Message{Data: []byte(`{
  "insertId": "eppsoda4",
  "jsonPayload": {
    "detectionCategory": {
      "ruleName": "bad_ip"
    },
    "affectedResources": [
      {
        "gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/test-project"
      }
    ],
    "properties": {
			"project_id": "foo-test",
      "location": "test-zone",
      "sourceInstance": "/projects/test-project/zones/test-zone/instances/instance1"
    }
  },
  "logName": "projects/test-project/logs/threatdetection.googleapis.com%2Fdetection"
}`)}
)

func TestCreateSnapshot(t *testing.T) {
	ctx := context.Background()

	var (
		// TODO(tomfitzgerald): Consider migrating to https://github.com/tflach/clockwork.
		fiveMinAgo       = time.Now().Add(-time.Minute * 5).Format(time.RFC3339)
		expectedSnapshot = map[string]compute.Snapshot{
			"sample-disk-name": {
				Description:       "Snapshot of sample-disk-name",
				Name:              "forensic-snapshots-bad-ip-sample-disk-name",
				CreationTimestamp: time.Now().Format(time.RFC3339),
			},
		}
		expectedSnapshot2 = map[string]compute.Snapshot{
			"sample-disk-name": {
				Description:       "Snapshot of sample-disk-name",
				Name:              "forensic-snapshots-bad-ip-sample-disk-name",
				CreationTimestamp: time.Now().Format(time.RFC3339),
			},
			"sample-disk-name2": {
				Description:       "Snapshot of sample-disk-name2",
				Name:              "forensic-snapshots-bad-ip-sample-disk-name2",
				CreationTimestamp: time.Now().Format(time.RFC3339),
			},
		}
		diskName = "sample-disk-name"
		// snapshotName is the expected snapshot name, default prefix, rule name and disk name.
		snapshotName = "forensic-snapshots-bad-ip-sample-disk-name"
	)
	test := []struct {
		name                  string
		existingProjectDisks  []*compute.Disk
		existingDiskSnapshots []*compute.Snapshot
		expectedSnapshots     map[string]compute.Snapshot
	}{
		{
			name: "generate disk snapshot (1 disk and 1 snapshot)",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot,
		},
		{
			name: "generate disk snapshot (1 disk and 2 snapshot)",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
				createSs(snapshotName, fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot,
		},
		{
			name: "generate disk snapshot (2 disk and 1 snapshot)",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
				createDisk("sample-disk-name2", "instance1"),
			},
			existingDiskSnapshots: []*compute.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot2,
		},
		{
			name: "generate disk snapshot (2 disk and 2 snapshot)",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
				createDisk("sample-disk-name2", "instance1"),
			},
			existingDiskSnapshots: []*compute.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
				createSs("forensic-snapshots-bad-ip-sample-disk-name2", fiveMinAgo, "sample-disk-name2"),
			},
			expectedSnapshots: expectedSnapshot2,
		},
		{
			name: "snapshotName preffix is different so generate disk snapshot",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.Snapshot{
				createSs("forensic-snapshots-bad-domain-simple-disk-name", fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot,
		},
		{
			name: "existing snapshot is new, skip",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.Snapshot{
				createSs(snapshotName, time.Now().Add(-time.Minute*2).Format(time.RFC3339), diskName),
			},
			expectedSnapshots: make(map[string]compute.Snapshot),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			loggerStub := &stubs.LoggerStub{}
			l := entities.NewLogger(loggerStub)
			computeStub := &stubs.ComputeStub{}
			computeStub.SavedCreateSnapshots = make(map[string]compute.Snapshot)
			computeStub.StubbedListDisks = &compute.DiskList{Items: tt.existingProjectDisks}
			computeStub.StubbedListProjectSnapshots = &compute.SnapshotList{Items: tt.existingDiskSnapshots}
			resourceManagerStub := &stubs.ResourceManagerStub{}
			storageStub := &stubs.StorageStub{}
			h := entities.NewHost(computeStub)
			r := entities.NewResource(resourceManagerStub, storageStub)
			if err := CreateSnapshot(ctx, sampleFinding, r, h, l); err != nil {
				t.Errorf("%s failed to create snapshot :%q", tt.name, err)
			}
			if diff := cmp.Diff(computeStub.SavedCreateSnapshots, tt.expectedSnapshots); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedSnapshots, computeStub.SavedCreateSnapshots)
			}
		})
	}
}

func createDisk(name, instance string) *compute.Disk {
	return &compute.Disk{
		Name:     name,
		SelfLink: "/projects/test-project/zones/test-zone/disks/" + name,
		Users:    []string{"/projects/test-project/zones/test-zone/instances/" + instance},
	}
}

func createSs(name, time, disk string) *compute.Snapshot {
	return &compute.Snapshot{
		Name:              name,
		CreationTimestamp: time,
		SourceDisk:        "/projects/test-project/zones/test-zone/disks/" + disk,
	}
}
