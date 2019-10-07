output "automation-service-account" {
  value = google_service_account.automation-service-account.email
}

output "gcf-bucket-name" {
  value = google_storage_bucket.gcf_bucket.name
}

output "gcf-object-name" {
  value = google_storage_bucket_object.gcf_object.name
}
