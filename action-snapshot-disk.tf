# Package automation contains the Cloud Function code to automate actions.

# Copyright 2019 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# 	https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
resource "google_cloudfunctions_function" "snapshot_disk_function" {
  name                  = "SnapshotDisk"
  description           = "Takes a snapshot of a GCE disk."
  runtime               = "go112"
  available_memory_mb   = 128
  source_archive_bucket = "${google_storage_bucket.snapshot_disk_bucket.name}"
  source_archive_object = "${google_storage_bucket_object.snapshot_storage_bucket_object.name}"
  timeout               = 60
  project               = "${var.automation-project}"
  region                = "${local.region}"
  entry_point           = "SnapshotDisk"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "${local.findings-topic}"
  }
}

resource "google_storage_bucket" "snapshot_disk_bucket" {
  name       = "${var.automation-project}-snapshot-disk"
  depends_on = ["local_file.cloudfunction-key-file"]
}

resource "google_storage_bucket_object" "snapshot_storage_bucket_object" {
  name   = "create_snapshot.zip"
  bucket = "${google_storage_bucket.snapshot_disk_bucket.name}"
  source = "${path.root}/deploy/create_snapshot.zip"
}

data "archive_file" "snapshot_cloud_function_zip" {
  type        = "zip"
  source_dir  = "${path.root}"
  output_path = "${path.root}/deploy/create_snapshot.zip"
  depends_on  = ["local_file.cloudfunction-key-file"]
  excludes    = ["deploy", ".git", ".terraform"]
}

# Role "compute.instanceAdmin" required to get disk lists and create snapshots for GCE instances.
# This must be placed on every project that you want to allow automated snapshots to be taken.
# This is used in functions/create_snapshot.go which creates new snapshots of the disk in the event
# of certain detectors triggering. These snapshots can help analysis of the event as the disk is
# captured at the time the activity occurred. This binding can be removed if the action is not
# being used.
#
# TODO: Remove these project declarations and instead support folders or org level grants.
resource "google_project_iam_binding" "gce-snapshot-bind-automation-project" {
  project = "${var.automation-project}"
  role    = "roles/compute.instanceAdmin.v1"
  members = ["serviceAccount:${google_service_account.automation-service-account.email}"]
}

resource "google_project_iam_binding" "gce-snapshot-bind-findings-project" {
  project = "${var.findings-project}"
  role    = "roles/compute.instanceAdmin.v1"
  members = ["serviceAccount:${google_service_account.automation-service-account.email}"]
}
