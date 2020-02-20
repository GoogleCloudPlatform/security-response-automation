# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# 	https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
resource "google_cloudfunctions_function" "create-disk-snapshot" {
  name                  = "SnapshotDisk"
  description           = "Takes a snapshot of a GCE disk."
  runtime               = "go111"
  available_memory_mb   = 128
  source_archive_bucket = var.setup.gcf-bucket-name
  source_archive_object = var.setup.gcf-object-name
  timeout               = 360
  project               = var.setup.automation-project
  region                = var.setup.region
  entry_point           = "SnapshotDisk"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "threat-findings-create-disk-snapshot"
  }
}

# Required to retrieve ancestry for projects within this folder.
resource "google_folder_iam_member" "roles-viewer" {
  count = length(var.folder-ids)

  folder = "folders/${var.folder-ids[count.index]}"
  role   = "roles/viewer"
  member = "serviceAccount:${var.setup.automation-service-account}"
}

# Used to create snapshots.
resource "google_folder_iam_member" "roles-compute-admin" {
  count = length(var.folder-ids)

  folder = "folders/${var.folder-ids[count.index]}"
  role   = "roles/compute.admin"
  member = "serviceAccount:${var.setup.automation-service-account}"
}

# Grant the service account permission create disks in the target project ID.
resource "google_project_iam_member" "turbinia-create-disks" {
  role    = "roles/compute.instanceAdmin"
  project = var.target-project-id
  member  = "serviceAccount:${var.setup.automation-service-account}"
}

# PubSub topic to trigger this automation.
resource "google_pubsub_topic" "topic" {
  name    = "threat-findings-create-disk-snapshot"
  project = var.setup.automation-project
}

# Grant the service account permission to publish to this topic.
resource "google_project_iam_member" "log-writer-pubsub" {
  role    = "roles/pubsub.editor"
  project = var.setup.automation-project
  member  = "serviceAccount:${var.setup.automation-service-account}"
}
