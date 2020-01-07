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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/googlecloudplatform/security-response-automation/clients/stubs"
	"github.com/googlecloudplatform/security-response-automation/services"
	compute "google.golang.org/api/compute/v1"
)

func TestCreateSnapshot(t *testing.T) {
	ctx := context.Background()

	var (
		// TODO(tomfitzgerald): Consider migrating to https://github.com/tflach/clockwork.
		fiveMinAgo       = time.Now().Add(-time.Minute * 5).Format(time.RFC3339)
		now              = time.Now().Format(time.RFC3339)
		expectedSnapshot = map[string]compute.Snapshot{
			"sample-disk-name": {
				Description:       "Snapshot of sample-disk-name",
				Name:              "forensic-snapshots-bad-ip-sample-disk-name",
				CreationTimestamp: now,
			},
		}
		expectedSnapshot2 = map[string]compute.Snapshot{
			"sample-disk-name": {
				Description:       "Snapshot of sample-disk-name",
				Name:              "forensic-snapshots-bad-ip-sample-disk-name",
				CreationTimestamp: now,
			},
			"sample-disk-name2": {
				Description:       "Snapshot of sample-disk-name2",
				Name:              "forensic-snapshots-bad-ip-sample-disk-name2",
				CreationTimestamp: now,
			},
		}
		diskName = "sample-disk-name"
		// snapshotName is the expected snapshot name, default prefix, rule name and disk name.
		snapshotName  = "forensic-snapshots-bad-ip-sample-disk-name"
		snapshotName2 = "forensic-snapshots-bad-ip-sample-disk-name2"
		// snapshotTarget is the project where the snapshot should be copied to.
		snapshotTarget = "foo-project-123"
	)
	test := []struct {
		name                  string
		existingProjectDisks  []*compute.Disk
		existingDiskSnapshots []*compute.SnapshotList
		expectedSnapshots     map[string]compute.Snapshot
		// configuredSnapshotTarget is the snapshot destination as optionally configured.
		configuredSnapshotTarget string
		// expectedSnapshotTarget is where the snapshot was actually saved.
		expectedSnapshotTarget string
		// diskInsertCalled is if the DiskInsert call was actually called.
		diskInsertCalled bool
	}{
		{
			name: "generate disk snapshot without configuring dest project",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName, now, diskName)}},
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName)}},
			},
			expectedSnapshots:        expectedSnapshot,
			expectedSnapshotTarget:   "",
			configuredSnapshotTarget: "",
			diskInsertCalled:         false,
		},
		{
			name: "generate disk snapshot 1 existing disk and 1 snapshot",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName, now, diskName)}},
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName)}},
			},
			expectedSnapshots:        expectedSnapshot,
			expectedSnapshotTarget:   snapshotTarget,
			configuredSnapshotTarget: snapshotTarget,
			diskInsertCalled:         true,
		},
		{
			name: "generate disk snapshot 1 existing disk and 2 snapshot",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName), createSs(snapshotName, now, diskName)}},
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName), createSs(snapshotName, fiveMinAgo, diskName)}},
			},
			expectedSnapshots:        expectedSnapshot,
			expectedSnapshotTarget:   snapshotTarget,
			configuredSnapshotTarget: snapshotTarget,
			diskInsertCalled:         true,
		},
		{
			name: "generate disk snapshot 2 existing disks and 1 snapshot",
			existingProjectDisks: []*compute.Disk{
				createDisk("sample-disk-name", "instance1"),
				createDisk("sample-disk-name2", "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName2, now, "sample-disk-name2")}},
				{Items: []*compute.Snapshot{createSs(snapshotName, now, diskName)}},
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName)}},
			},
			expectedSnapshots:        expectedSnapshot2,
			expectedSnapshotTarget:   snapshotTarget,
			configuredSnapshotTarget: snapshotTarget,
			diskInsertCalled:         true,
		},
		{
			name: "create new snapshot for 2 existing disks and snapshots",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
				createDisk("sample-disk-name2", "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName, now, diskName), createSs("forensic-snapshots-bad-ip-sample-disk-name2", now, "sample-disk-name2")}},
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName), createSs("forensic-snapshots-bad-ip-sample-disk-name2", fiveMinAgo, "sample-disk-name2")}},
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName), createSs("forensic-snapshots-bad-ip-sample-disk-name2", fiveMinAgo, "sample-disk-name2")}},
			},
			expectedSnapshots:        expectedSnapshot2,
			expectedSnapshotTarget:   snapshotTarget,
			configuredSnapshotTarget: snapshotTarget,
			diskInsertCalled:         true,
		},
		{
			name: "prefix is different so generate disk snapshot",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs("forensic-snapshots-bad-ip-sample-disk-name", fiveMinAgo, diskName)}},
				{Items: []*compute.Snapshot{createSs("forensic-snapshots-bad-domain-sample-disk-name", fiveMinAgo, diskName)}},
			},
			expectedSnapshots:        expectedSnapshot,
			expectedSnapshotTarget:   snapshotTarget,
			configuredSnapshotTarget: snapshotTarget,
			diskInsertCalled:         true,
		},
		{
			name: "existing snapshot is new, skip",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName, time.Now().Add(-time.Minute*2).Format(time.RFC3339), diskName)}},
			},
			expectedSnapshots:        make(map[string]compute.Snapshot),
			expectedSnapshotTarget:   "",
			configuredSnapshotTarget: snapshotTarget,
			diskInsertCalled:         true,
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			svcs, computeStub := createSnapshotSetup()
			computeStub.StubbedListDisks = &compute.DiskList{Items: tt.existingProjectDisks}
			computeStub.StubbedListProjectSnapshots = tt.existingDiskSnapshots
			values := &Values{
				ProjectID:     "project-id-123",
				DestProjectID: tt.configuredSnapshotTarget,
				RuleName:      "bad_ip",
				Instance:      "instance1",
				Zone:          "test-zone",
			}
			if _, err := Execute(ctx, values, &Services{
				Host:   svcs.Host,
				Logger: svcs.Logger,
			}); err != nil {
				t.Errorf("%s failed to create snapshot: %q", tt.name, err)
			}
			if !tt.diskInsertCalled && computeStub.DiskInsertCalled {
				t.Errorf("%s failed: should not have called DiskInsert", tt.name)
			}
			if computeStub.SavedDiskInsertDst != tt.expectedSnapshotTarget {
				t.Errorf("%s failed: exp:%s got:%s", tt.name, computeStub.SavedDiskInsertDst, computeStub.SavedDiskInsertDst)
			}
			if diff := cmp.Diff(computeStub.SavedCreateSnapshots, tt.expectedSnapshots); diff != "" {
				t.Errorf("%v failed\n exp:%v\n got:%v", tt.name, tt.expectedSnapshots, diff)
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
		Id:                012345,
		LabelFingerprint:  "foo123",
		Name:              name,
		CreationTimestamp: time,
		SourceDisk:        "/projects/test-project/zones/test-zone/disks/" + disk,
	}
}

func createSnapshotSetup() (*services.Global, *stubs.ComputeStub) {
	loggerStub := &stubs.LoggerStub{}
	log := services.NewLogger(loggerStub)
	computeStub := &stubs.ComputeStub{}
	computeStub.SavedCreateSnapshots = make(map[string]compute.Snapshot)
	resourceManagerStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	h := services.NewHost(computeStub)
	r := services.NewResource(resourceManagerStub, storageStub)
	return &services.Global{Host: h, Resource: r, Logger: log}, computeStub
}
