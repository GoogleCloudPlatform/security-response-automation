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
resource "google_logging_project_sink" "sink" {
  name                   = "sink-threat-findings"
  destination            = "pubsub.googleapis.com/projects/${var.automation-project}/topics/${local.findings-topic}"
  filter                 = "resource.type = threat_detector"
  unique_writer_identity = true
  project                = "${var.findings-project}"
}

resource "google_project_iam_binding" "log-writer-pubsub" {
  role    = "roles/pubsub.publisher"
  project = "${var.automation-project}"

  members = [
    "${google_logging_project_sink.sink.writer_identity}",
  ]
}

resource "google_pubsub_topic" "topic" {
  name = "${local.findings-topic}"
}
