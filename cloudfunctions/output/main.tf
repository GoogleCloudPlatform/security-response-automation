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

resource "google_cloudfunctions_function" "output" {
  name                  = "Output"
  description           = "Output router."
  runtime               = "go111"
  available_memory_mb   = 128
  source_archive_bucket = var.setup.gcf-bucket-name
  source_archive_object = var.setup.gcf-object-name
  timeout               = 60
  project               = var.setup.automation-project
  region                = var.setup.region
  entry_point           = "Output"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "threat-findings-output"
  }
}

resource "google_project_iam_member" "router-pubsub-writer" {
  role    = "roles/pubsub.publisher"
  project = var.setup.automation-project
  member  = "serviceAccount:${var.setup.automation-service-account}"
}
