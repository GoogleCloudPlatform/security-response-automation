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
locals {
  region         = "us-central1"
  findings-topic = "threat-findings"
  cscc-findings  = "cscc-notifications"
  golang-runtime = "go111"

  // GCS bucket to store GCF code.
  bucket-name = "${var.automation-project}-cloud-functions-code"
}

provider "google" {
  project = "${var.automation-project}"
  region  = "${local.region}"
}

resource "google_storage_bucket" "gcf_bucket" {
  name       = "${local.bucket-name}"
  depends_on = ["local_file.cloudfunction-key-file"]
}

resource "google_storage_bucket_object" "gcf_object" {
  name   = "functions.zip"
  bucket = "${google_storage_bucket.gcf_bucket.name}"
  source = "${path.root}/deploy/functions.zip"
}

data "archive_file" "cloud_functions_zip" {
  type        = "zip"
  source_dir  = "${path.root}"
  output_path = "${path.root}/deploy/functions.zip"
  depends_on  = ["local_file.cloudfunction-key-file"]
  excludes    = ["deploy", ".git", ".terraform"]
}
