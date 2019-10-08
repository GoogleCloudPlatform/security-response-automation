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
resource "google_cloudfunctions_function" "disable_firewall_function" {
  name                  = "DisableFirewall"
  description           = "Disable a firewall rule."
  runtime               = "go111"
  available_memory_mb   = 128
  source_archive_bucket = "${var.gcf-bucket-name}"
  source_archive_object = "${var.gcf-object-name}"
  timeout               = 60
  project               = "${var.automation-project}"
  region                = "${var.region}"
  entry_point           = "DisableFirewallRule"

  event_trigger {
    event_type = "providers/cloud.pubsub/eventTypes/topic.publish"
    resource   = "${var.findings-topic}"
  }
}


# Role "roles/compute.securityAdmin" required to get and patch Firewall rules.
# This role can be applied on individual projects, folders or at the organization level.
# This is used in functions/disable_firewall.go which disable firewall rules in the event
# of certain detectors triggering. This binding can be removed if the action is not
# being used.
#
# TODO: Support folder level grants.
resource "google_organization_iam_member" "disable-firewall-bind-findings-organization" {
  org_id = "${var.organization-id}"
  role   = "roles/compute.securityAdmin"

  member = "serviceAccount:${var.automation-service-account}"
}
