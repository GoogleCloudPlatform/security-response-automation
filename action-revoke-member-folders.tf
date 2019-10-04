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
  runtime               = "${local.golang-runtime}"
  available_memory_mb   = 128
  source_archive_bucket = "${google_storage_bucket.gcf_bucket.name}"
  source_archive_object = "${google_storage_bucket_object.gcf_object.name}"
  timeout               = 60
  project               = "${var.automation-project}"
  region                = "${local.region}"
  entry_point           = "RevokeExternalGrantsFolders"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "${local.findings-topic}"
  }
}

# Required by RevokeExternalGrantsFolders to revoke IAM grants on projects within this folder.
resource "google_folder_iam_binding" "revoke_member_cloudfunction-folder-bind" {
  folder  = "folders/${var.revoke-within-folder}"
  role    = "roles/resourcemanager.folderAdmin"
  members = ["serviceAccount:${google_service_account.automation-service-account.email}"]
}

# In order for this GCF to be able to enumerate and check to see if the affected project is within
# the specified folder `resourcemanager.projects.get` is required. The function will attempt to
# make this call but if the permission is not granted the function will fail.
#
# You could grant `resourcemanager.projects.get` to the service account at the organization level
# or let it fail which also means the project is outside of the folder you care about.
#
# In this example we'll grant `roles/viewer` which has this permission to the folder.
resource "google_folder_iam_binding" "revoke_member_viewer_cloudfunction-folder-bind" {
  folder  = "folders/${var.revoke-within-folder}"
  role    = "roles/viewer"
  members = ["serviceAccount:${google_service_account.automation-service-account.email}"]
}
