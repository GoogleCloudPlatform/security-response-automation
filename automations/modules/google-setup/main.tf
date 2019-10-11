locals {
  // GCS bucket to store GCF code.
  bucket-name = "${var.automation-project}-cloud-functions-code"
}

// GCF
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

// service accounts
resource "google_service_account" "automation-service-account" {
  account_id   = "automation-service-account"
  display_name = "Service account used by automation Cloud Function"
  project      = "${var.automation-project}"
}

resource "google_service_account_key" "cloudfunction-key" {
  service_account_id = "${google_service_account.automation-service-account.name}"
}

resource "local_file" "cloudfunction-key-file" {
  content  = "${base64decode(google_service_account_key.cloudfunction-key.private_key)}"
  filename = "./credentials/auth.json"
}

// sinks
resource "google_logging_project_sink" "sink" {
  name                   = "sink-threat-findings"
  destination            = "pubsub.googleapis.com/projects/${var.automation-project}/topics/threat-findings"
  filter                 = "resource.type = threat_detector"
  unique_writer_identity = true
  project                = "${var.findings-project}"
}

resource "google_project_iam_member" "log-writer-pubsub" {
  role    = "roles/pubsub.publisher"
  project = "${var.automation-project}"
  member  = "${google_logging_project_sink.sink.writer_identity}"
}

resource "google_pubsub_topic" "topic" {
  name = "threat-findings"
}

// CSCC notifications.
resource "google_pubsub_topic" "cscc-notifications-topic" {
  name = "${var.cscc-notifications-topic-prefix}-topic"
}

resource "google_pubsub_subscription" "cscc-notifications-subscription" {
  name                 = "${var.cscc-notifications-topic-prefix}-subscription"
  topic                = "${google_pubsub_topic.cscc-notifications-topic.name}"
  ack_deadline_seconds = 20
}

resource "google_organization_iam_member" "cscc-notifications-sa" {
  org_id = "${var.organization-id}"
  role   = "roles/securitycenter.notificationConfigEditor"
  member = "serviceAccount:${google_service_account.automation-service-account.email}"
}

resource "google_project_iam_member" "stackdriver-writer" {
  project = "${var.automation-project}"
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.automation-service-account.email}"
}
