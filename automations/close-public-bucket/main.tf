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
resource "google_cloudfunctions_function" "close-bucket" {
  name                  = "CloseBucket"
  description           = "Removes users that enable public viewing of GCS buckets."
  runtime               = "go111"
  available_memory_mb   = 128
  source_archive_bucket = "${var.gcf-bucket-name}"
  source_archive_object = "${var.gcf-object-name}"
  timeout               = 60
  project               = "${var.automation-project}"
  region                = "${var.region}"
  entry_point           = "CloseBucket"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "${var.cscc-notifications-topic}"
  }

  environment_variables = {
    folder_ids = "${join(",", var.folder-ids)}"
  }
}

# Required to retrieve ancestry for projects within this folder.
resource "google_folder_iam_binding" "roles-viewer" {
  count = length(var.folder-ids)

  folder  = "folders/${var.folder-ids[count.index]}"
  role    = "roles/viewer"
  members = ["serviceAccount:${var.automation-service-account}"]
}

# Required to modify buckets within this folder.
resource "google_folder_iam_binding" "roles-storage-admin" {
  count = length(var.folder-ids)

  folder  = "folders/${var.folder-ids[count.index]}"
  role    = "roles/storage.admin"
  members = ["serviceAccount:${var.automation-service-account}"]
}
