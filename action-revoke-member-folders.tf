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
resource "google_cloudfunctions_function" "revoke_member_function" {
  name                  = "RevokeExternalGrantsFolders"
  description           = "Revokes IAM Event Threat Detection anomalous IAM grants."
  runtime               = "go112"
  available_memory_mb   = 128
  source_archive_bucket = "${google_storage_bucket.revoke_member_bucket.name}"
  source_archive_object = "${google_storage_bucket_object.revoke_storage_bucket_object.name}"
  timeout               = 60
  project               = "${var.automation-project}"
  region                = "${local.region}"
  entry_point           = "RevokeExternalGrantsFolders"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "${local.findings-topic}"
  }
}

resource "google_storage_bucket" "revoke_member_bucket" {
  name       = "${var.automation-project}-revoke-member-folders"
  depends_on = ["local_file.cloudfunction-key-file"]
}

resource "google_storage_bucket_object" "revoke_storage_bucket_object" {
  name   = "revoke_member_folders.zip"
  bucket = "${google_storage_bucket.revoke_member_bucket.name}"
  source = "${path.root}/deploy/revoke_member_folders.zip"
}

data "archive_file" "revoke_member_zip" {
  type        = "zip"
  source_dir  = "${path.root}"
  output_path = "${path.root}/deploy/revoke_member_folders.zip"
  depends_on  = ["local_file.cloudfunction-key-file"]
  excludes    = ["deploy", ".git", ".terraform"]
}

# Required by RevokeExternalGrantsFolders to revoke IAM grants on projects within this folder.
resource "google_folder_iam_binding" "cloudfunction-folder-bind" {
  folder  = "folders/${var.revoke-within-folder}"
  role    = "roles/resourcemanager.folderAdmin"
  members = ["serviceAccount:${google_service_account.automation-service-account.email}"]
}
