output "automation-service-account" {
  value = google_service_account.automation-service-account.email
}

output "gcf-bucket-name" {
  value = google_storage_bucket.gcf_bucket.name
}

output "gcf-object-name" {
  value = google_storage_bucket_object.gcf_object.name
}

output "automation-project" {
  value = var.automation-project
}

output "cscc-notifications-topic-prefix" {
  value = var.cscc-notifications-topic-prefix
}

output "region" {
  value = var.region
}
