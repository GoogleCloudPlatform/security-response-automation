variable "findings-topic" {
  type = "string"
}

variable "disallowed-domains" {
  type        = list(string)
  description = "Domain names you want to revoke if found in a finding."
}

variable "folder-ids" {
  type        = list(string)
  description = "Remove public users from buckets if they are within the given folder IDs."
}

variable "automation-project" {
  type = "string"
}

variable "automation-service-account" {
  type = "string"
}

variable "gcf-bucket-name" {
  type = "string"
}

variable "gcf-object-name" {
  type = "string"
}

variable "region" {
  type = "string"
}
