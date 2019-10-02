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
resource "google_cloudfunctions_function" "close_bucket_function" {
  name                  = "CloseBucket"
  description           = "Removes users that enable public viewing of GCS buckets."
  runtime               = "${local.golang-runtime}"
  available_memory_mb   = 128
  source_archive_bucket = "${google_storage_bucket.gcf_bucket.name}"
  source_archive_object = "${google_storage_bucket_object.gcf_object.name}"
  timeout               = 60
  project               = "${var.automation-project}"
  region                = "${local.region}"
  entry_point           = "CloseBucket"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "${google_pubsub_topic.cscc-notifications-topic.name}"
  }
}

# Required to retrieve ancestry for projects within this folder.
resource "google_folder_iam_binding" "close_bucket_ancestry_cloudfunction-folder-bind" {
  folder  = "folders/${var.revoke-within-folder}"
  role    = "roles/viewer"
  members = ["serviceAccount:${google_service_account.automation-service-account.email}"]
}

# Required to modify buckets within this folder.
resource "google_folder_iam_binding" "close_bucket_storage_admin_cloudfunction-folder-bind" {
  folder  = "folders/${var.revoke-within-folder}"
  role    = "roles/storage.admin"
  members = ["serviceAccount:${google_service_account.automation-service-account.email}"]
}
