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
  runtime               = "go113"
  available_memory_mb   = 128
  source_archive_bucket = var.setup.gcf-bucket-name
  source_archive_object = var.setup.gcf-object-name
  timeout               = 60
  project               = var.setup.automation-project
  region                = var.setup.region
  entry_point           = "CloseBucket"
  service_account_email = var.setup.automation-service-account

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = "threat-findings-close-bucket"
  }
  environment_variables = {
    GCP_PROJECT = var.setup.automation-project
  }
}

# PubSub topic to trigger this automation.
resource "google_pubsub_topic" "topic" {
  name    = "threat-findings-close-bucket"
  project = var.setup.automation-project
}

# Required to retrieve ancestry for projects within this folder.
resource "google_folder_iam_member" "roles-viewer" {
  count = length(var.folder-ids)

  folder = "folders/${var.folder-ids[count.index]}"
  role   = "roles/viewer"
  member = "serviceAccount:${var.setup.automation-service-account}"
}

# Required to modify buckets within this folder.
resource "google_folder_iam_member" "roles-storage-admin" {
  count = length(var.folder-ids)

  folder = "folders/${var.folder-ids[count.index]}"
  role   = "roles/storage.admin"
  member = "serviceAccount:${var.setup.automation-service-account}"
}

resource "google_project_service" "storage_api" {
  project                    = var.setup.automation-project
  service                    = "storage-api.googleapis.com"
  disable_dependent_services = false
  disable_on_destroy         = false
}
