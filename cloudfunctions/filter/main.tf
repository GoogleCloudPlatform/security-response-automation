// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.# Copyright 2019 Google LLC

resource "google_cloudfunctions_function" "filter" {
  name                  = "Filter"
  description           = "Filters finding JSON for exceptions, baselines and false positives using Rego"
  runtime               = "go113"
  available_memory_mb   = 512
  source_archive_bucket = var.setup.gcf-bucket-name
  source_archive_object = var.setup.gcf-object-name
  timeout               = 60
  project               = var.setup.automation-project
  region                = var.setup.region
  entry_point           = "Filter"
  service_account_email = var.setup.automation-service-account

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = var.setup.findings-topic-id
  }
  environment_variables = {
    OUTPUT_TOPIC = var.setup.router-topic-name
    GCP_PROJECT  = var.setup.automation-project
  }
}

resource "google_project_iam_member" "filter-pubsub-writer" {
  role    = "roles/pubsub.editor"
  project = var.setup.automation-project
  member  = "serviceAccount:${var.setup.automation-service-account}"
}

resource "null_resource" "generate" {
  provisioner "local-exec" {
    command = "go generate ./..."
  }
  triggers = {
    // Forces this to trigger every apply
    build_number = timestamp()
  }
}
