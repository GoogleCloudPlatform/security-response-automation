/*
Package actions provides the implementation of automated actions.

Copyright 2019 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package actions

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/threat-automation/automation/clients"

	"cloud.google.com/go/pubsub"

	cs "google.golang.org/api/compute/v1"
)

var (
	fiveMinAgo = time.Now().Add(-time.Minute * 5).Format(time.RFC3339)

	sampleFinding = pubsub.Message{Data: []byte(`{
                "insertId": "eppsoda4",
                "jsonPayload": {"detectionCategory": {"ruleName": "bad_ip"},
        "affectedResources":[{"gcpResourceName": "//cloudresourcemanager.googleapis.com/projects/test-project"}],
                "properties": {
                        "location": "test-zone",
                        "sourceInstance": "/projects/test-project/zones/test-zone/instances/instance1"
		}
        }, "logName": "projects/test-project/logs/threatdetection.googleapis.com%2Fdetection"}`)}
)

func TestCreateSnapshot(t *testing.T) {
	ctx := context.Background()

	var (
		expectedSnapshot = map[string]cs.Snapshot{
			"sample-disk-name": {
				Description:       "Snapshot of sample-disk-name",
				Name:              "forensic-snapshots-bad-ip-sample-disk-name",
				CreationTimestamp: time.Now().Format(time.RFC3339),
			},
		}
		expectedSnapshot2 = map[string]cs.Snapshot{
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
		existingProjectDisks  []*cs.Disk
		existingDiskSnapshots []*cs.Snapshot
		expectedSnapshots     map[string]cs.Snapshot
	}{
		{
			name: "generate disk snapshot (1 disk and 1 snapshot)",
			existingProjectDisks: []*cs.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*cs.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot,
		},
		{
			name: "generate disk snapshot (1 disk and 2 snapshot)",
			existingProjectDisks: []*cs.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*cs.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
				createSs(snapshotName, fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot,
		},
		{
			name: "generate disk snapshot (2 disk and 1 snapshot)",
			existingProjectDisks: []*cs.Disk{
				createDisk(diskName, "instance1"),
				createDisk("sample-disk-name2", "instance1"),
			},
			existingDiskSnapshots: []*cs.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot2,
		},
		{
			name: "generate disk snapshot (2 disk and 2 snapshot)",
			existingProjectDisks: []*cs.Disk{
				createDisk(diskName, "instance1"),
				createDisk("sample-disk-name2", "instance1"),
			},
			existingDiskSnapshots: []*cs.Snapshot{
				createSs(snapshotName, fiveMinAgo, diskName),
				createSs("forensic-snapshots-bad-ip-sample-disk-name2", fiveMinAgo, "sample-disk-name2"),
			},
			expectedSnapshots: expectedSnapshot2,
		},
		{
			name: "snapshotName preffix is different so generate disk snapshot",
			existingProjectDisks: []*cs.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*cs.Snapshot{
				createSs("forensic-snapshots-bad-domain-simple-disk-name", fiveMinAgo, diskName),
			},
			expectedSnapshots: expectedSnapshot,
		},
		{
			name: "existing snapshot is new, skip",
			existingProjectDisks: []*cs.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*cs.Snapshot{
				createSs(snapshotName, time.Now().Add(-time.Minute*2).Format(time.RFC3339), diskName),
			},
			expectedSnapshots: make(map[string]cs.Snapshot),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {

			mock := clients.NewMockClients()
			mock.AddListDisksFake(tt.existingProjectDisks)
			mock.AddListProjectSnapshotsFake(tt.existingDiskSnapshots)

			if err := CreateSnapshot(ctx, sampleFinding, mock); err != nil {
				t.Errorf("failed to create snapshot :%q", err)
			}

			if !reflect.DeepEqual(mock.SavedCreateSnapshots, tt.expectedSnapshots) {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedSnapshots, mock.SavedCreateSnapshots)
			}
		})
	}
}

func createDisk(name, instance string) *cs.Disk {
	return &cs.Disk{
		Name:     name,
		SelfLink: "/projects/test-project/zones/test-zone/disks/" + name,
		Users:    []string{"/projects/test-project/zones/test-zone/instances/" + instance},
	}
}

func createSs(name, time, disk string) *cs.Snapshot {
	return &cs.Snapshot{
		Name:              name,
		CreationTimestamp: time,
		SourceDisk:        "/projects/test-project/zones/test-zone/disks/" + disk,
	}
}
