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
  source = "./automations/modules/google-setup"

  organization-id                 = "${var.organization-id}"
  automation-project              = "${var.automation-project}"
  findings-project                = "${var.findings-project}"
  cscc-notifications-topic-prefix = "${local.cscc-findings-topic}"
}

module "close_public_bucket" {
  source = "./automations/close-public-bucket"

  automation-project         = "${var.automation-project}"
  automation-service-account = "${module.google-setup.automation-service-account}"
  cscc-notifications-topic   = "${local.cscc-findings-topic}-topic"
  gcf-bucket-name            = "${module.google-setup.gcf-bucket-name}"
  gcf-object-name            = "${module.google-setup.gcf-object-name}"
  organization-id            = "${var.automation-project}"
  region                     = "${local.region}"

  # Remove public users from any projects found by Security Health Analytics that are within the
  # following folder IDs.
  folder-ids = [
    "670032686187",
  ]
}

module "revoke_iam_grants" {
  source = "./automations/revoke-iam-grants"

  automation-project         = "${var.automation-project}"
  automation-service-account = "${module.google-setup.automation-service-account}"
  findings-topic             = "${local.findings-topic}"
  gcf-bucket-name            = "${module.google-setup.gcf-bucket-name}"
  gcf-object-name            = "${module.google-setup.gcf-object-name}"
  region                     = "${local.region}"

  folder-ids = [
    "670032686187",
  ]
  disallowed-domains = [
    "gmail.com",
    "test.com",
  ]
}

module "create_disk_snapshot" {
  source = "./automations/create-disk-snapshot"

  automation-project         = "${var.automation-project}"
  automation-service-account = "${module.google-setup.automation-service-account}"
  findings-topic             = "${local.findings-topic}"
  gcf-bucket-name            = "${module.google-setup.gcf-bucket-name}"
  gcf-object-name            = "${module.google-setup.gcf-object-name}"
  region                     = "${local.region}"

  organization-id = "${var.organization-id}"
}

module "disable_firewall_rule" {
  source = "./automations/disable-firewall-rule"

  automation-project         = "${var.automation-project}"
  automation-service-account = "${module.google-setup.automation-service-account}"
  findings-topic             = "${local.findings-topic}"
  gcf-bucket-name            = "${module.google-setup.gcf-bucket-name}"
  gcf-object-name            = "${module.google-setup.gcf-object-name}"
  region                     = "${local.region}"

    folder-ids = [
    "670032686187",
  ]
}
