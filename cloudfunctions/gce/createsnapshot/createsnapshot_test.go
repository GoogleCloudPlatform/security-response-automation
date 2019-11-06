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
	"github.com/googlecloudplatform/threat-automation/clients/stubs"
	"github.com/googlecloudplatform/threat-automation/entities"
	"golang.org/x/xerrors"
	compute "google.golang.org/api/compute/v1"
)

func TestReadFinding(t *testing.T) {
	const (
		validBadIP = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project",
					"instanceDetails": "/zones/zone-name/instances/source-instance-name"
				},
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
		missingProperties = `{
			"jsonPayload": {
				"detectionCategory": {
					"ruleName": "bad_ip"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
		wrongRule = `{
			"jsonPayload": {
				"properties": {
					"location": "us-central1",
					"project_id": "test-project",
					"instanceDetails": "/zones/zone-name/instances/source-instance-name"
				},
				"detectionCategory": {
					"ruleName": "something_else"
				}
			},
			"logName": "projects/test-project/logs/threatdetection.googleapis.com` + "%%2F" + `detection"
		}`
	)
	for _, tt := range []struct {
		name, rule, projectID, instance, zone string
		bytes                                 []byte
		expectedError                         error
	}{
		{name: "read", rule: "bad_ip", projectID: "test-project", zone: "zone-name", instance: "source-instance-name", expectedError: nil, bytes: []byte(validBadIP)},
		{name: "missing properties", rule: "", projectID: "", zone: "", instance: "", expectedError: entities.ErrValueNotFound, bytes: []byte(missingProperties)},
		{name: "wrong rule", rule: "", projectID: "", zone: "", instance: "", expectedError: entities.ErrUnsupportedFinding, bytes: []byte(wrongRule)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := ReadFinding(tt.bytes)
			if tt.expectedError == nil && err != nil {
				t.Errorf("%s failed: %q", tt.name, err)
			}
			if tt.expectedError != nil && err != nil && !xerrors.Is(err, tt.expectedError) {
				t.Errorf("%s failed: got:%q want:%q", tt.name, err, tt.expectedError)
			}
			if err == nil && r.RuleName != tt.rule {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.RuleName, tt.rule)
			}
			if err == nil && r.Instance != tt.instance {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.Instance, tt.instance)
			}
			if err == nil && r.Zone != tt.zone {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.Zone, tt.zone)
			}
			if err == nil && r.ProjectID != tt.projectID {
				t.Errorf("%s failed: got:%q want:%q", tt.name, r.ProjectID, tt.projectID)
			}
		})
	}
}

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
	)
	test := []struct {
		name                  string
		existingProjectDisks  []*compute.Disk
		existingDiskSnapshots []*compute.SnapshotList
		expectedSnapshots     map[string]compute.Snapshot
	}{
		{
			name: "generate disk snapshot 1 existing disk and 1 snapshot",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName, now, diskName)}},
				{Items: []*compute.Snapshot{createSs(snapshotName, fiveMinAgo, diskName)}},
			},
			expectedSnapshots: expectedSnapshot,
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
			expectedSnapshots: expectedSnapshot,
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
			expectedSnapshots: expectedSnapshot2,
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
			expectedSnapshots: expectedSnapshot2,
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
			expectedSnapshots: expectedSnapshot,
		},
		{
			name: "existing snapshot is new, skip",
			existingProjectDisks: []*compute.Disk{
				createDisk(diskName, "instance1"),
			},
			existingDiskSnapshots: []*compute.SnapshotList{
				{Items: []*compute.Snapshot{createSs(snapshotName, time.Now().Add(-time.Minute*2).Format(time.RFC3339), diskName)}},
			},
			expectedSnapshots: make(map[string]compute.Snapshot),
		},
	}
	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ent, computeStub := createSnapshotSetup()
			computeStub.StubbedListDisks = &compute.DiskList{Items: tt.existingProjectDisks}
			computeStub.StubbedListProjectSnapshots = tt.existingDiskSnapshots
<<<<<<< HEAD:cloudfunctions/gce/createsnapshot/createsnapshot_test.go
			values := &Values{
=======
			required := &Required{
>>>>>>> 8a7432ce21d4d9e9221a655d9a2905020835022e:cloudfunctions/createsnapshot/createsnapshot_test.go
				ProjectID: "foo-test",
				RuleName:  "bad_ip",
				Instance:  "instance1",
				Zone:      "test-zone",
			}
			if err := Execute(ctx, values, &Needed{
				Host:   ent.Host,
				Logger: ent.Logger,
			}); err != nil {
				t.Errorf("%s failed to create snapshot: %q", tt.name, err)
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

func createSnapshotSetup() (*entities.Entity, *stubs.ComputeStub) {
	loggerStub := &stubs.LoggerStub{}
	log := entities.NewLogger(loggerStub)
	computeStub := &stubs.ComputeStub{}
	computeStub.SavedCreateSnapshots = make(map[string]compute.Snapshot)
	resourceManagerStub := &stubs.ResourceManagerStub{}
	storageStub := &stubs.StorageStub{}
	h := entities.NewHost(computeStub)
	r := entities.NewResource(resourceManagerStub, storageStub)
	return &entities.Entity{Host: h, Resource: r, Logger: log}, computeStub
}
