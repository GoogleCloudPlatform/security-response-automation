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
  project = var.automation-project
  region  = local.region
}

module "google-setup" {
  source = "./terraform/setup/google-setup"

  region                          = local.region
  organization-id                 = var.organization-id
  automation-project              = var.automation-project
  findings-project                = var.findings-project
  cscc-notifications-topic-prefix = local.cscc-findings-topic
  findings-topic                  = local.findings-topic
  enable-scc-notification         = var.enable-scc-notification
}

module "filter" {
  source = "./cloudfunctions/filter"
  setup  = module.google-setup
}

module "router" {
  source     = "./cloudfunctions/router/"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "close_public_bucket" {
  source     = "./cloudfunctions/gcs/closebucket"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "revoke_iam_grants" {
  source     = "./cloudfunctions/iam/revoke"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "create_disk_snapshot" {
  source              = "./cloudfunctions/gce/createsnapshot"
  setup               = module.google-setup
  folder-ids          = var.folder-ids
  turbinia-project-id = ""
  turbinia-topic-name = ""
}

module "enable_bucket_only_policy" {
  source     = "./cloudfunctions/gcs/enablebucketonlypolicy"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "open_firewall" {
  source     = "./cloudfunctions/gce/openfirewall"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "remove_public_ip" {
  source     = "./cloudfunctions/gce/removepublicip"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "close_public_dataset" {
  source     = "./cloudfunctions/bigquery/closepublicdataset"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "close_public_cloud_sql" {
  source     = "./cloudfunctions/cloud-sql/removepublic"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "cloud-sql-require-ssl" {
  source     = "./cloudfunctions/cloud-sql/requiressl"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "disable_dashboard" {
  source     = "./cloudfunctions/gke/disabledashboard"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "update_password" {
  source     = "./cloudfunctions/cloud-sql/updatepassword"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

module "enable_audit_logs" {
  source     = "./cloudfunctions/iam/enableauditlogs"
  setup      = module.google-setup
  folder-ids = var.folder-ids
}

// TODO: enable again and fix IAM roles
//module "remove_non_org_members" {
//  source     = "./cloudfunctions/iam/removenonorgmembers"
//  setup      = module.google-setup
//  folder-ids = var.folder-ids
//}
