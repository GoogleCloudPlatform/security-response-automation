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
  name                  = "IAMRevoke"
  description           = "Revokes IAM Event Threat Detection anomalous IAM grants."
  runtime               = "go113"
  available_memory_mb   = 128
  source_archive_bucket = var.setup.gcf-bucket-name
  source_archive_object = var.setup.gcf-object-name
  timeout               = 60
  project               = var.setup.automation-project
  region                = var.setup.region
  entry_point           = "IAMRevoke"
  service_account_email = var.setup.automation-service-account

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = "threat-findings-iam-revoke"
  }
  environment_variables = {
    GCP_PROJECT = var.setup.automation-project
  }
}

# Required by IAMRevoke to revoke IAM grants on projects within this folder.
resource "google_folder_iam_member" "revoke_member_cloudfunction-folder-bind" {
  count = length(var.folder-ids)

  folder = "folders/${var.folder-ids[count.index]}"
  role   = "roles/resourcemanager.folderAdmin"
  member = "serviceAccount:${var.setup.automation-service-account}"
}

# Required to retrieve ancestry for projects within this folder.
resource "google_folder_iam_member" "revoke_member_viewer_cloudfunction-folder-bind" {
  count = length(var.folder-ids)

  folder = "folders/${var.folder-ids[count.index]}"
  role   = "roles/viewer"
  member = "serviceAccount:${var.setup.automation-service-account}"
}

# PubSub topic to trigger this automation.
resource "google_pubsub_topic" "topic" {
  name    = "threat-findings-iam-revoke"
  project = var.setup.automation-project
}

# Grant the service account permission to publish to this topic.
resource "google_project_iam_member" "log-writer-pubsub" {
  role    = "roles/pubsub.editor"
  project = var.setup.automation-project
  member  = "serviceAccount:${var.setup.automation-service-account}"
}
