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
  region              = "us-central1"
  cscc-findings-topic = "cscc-notifications"
  findings-topic      = "threat-findings"
}

provider "google" {
  project = "${var.automation-project}"
  region  = "${local.region}"
}

module "google-setup" {
  source = "./terraform/setup/google-setup"

  region                          = "${local.region}"
  organization-id                 = "${var.organization-id}"
  automation-project              = "${var.automation-project}"
  findings-project                = "${var.findings-project}"
  cscc-notifications-topic-prefix = "${local.cscc-findings-topic}"
  findings-topic                  = "${local.findings-topic}"
}

module "close_public_bucket" {
  source = "./terraform/automations/close-public-bucket"
  setup  = "${module.google-setup}"
  folder-ids = [
    "670032686187",
  ]
}

module "revoke_iam_grants" {
  source = "./terraform/automations/revoke-iam-grants"
  setup  = "${module.google-setup}"
  folder-ids = [
    "670032686187",
  ]
}

module "create_disk_snapshot" {
  source = "./terraform/automations/create-disk-snapshot"
  setup  = "${module.google-setup}"
}

module "open_firewall" {
  source = "./terraform/automations/disable-firewall"
  setup  = "${module.google-setup}"
  folder-ids = [
    "670032686187",
  ]
}

module "remove_public_ip" {
  source = "./terraform/automations/remove-public-ip"
  setup  = "${module.google-setup}"
  folder-ids = [
    "670032686187",
  ]
}

module "close_public_cloud_sql" {
  source = "./terraform/automations/close-public-cloud-sql"
  setup  = "${module.google-setup}"
  folder-ids = [
    "670032686187",
  ]
}

module "disable_dashboard" {
  source = "./terraform/automations/disable-dashboard"
  setup  = "${module.google-setup}"
  folder-ids = [
    "670032686187",
  ]
}