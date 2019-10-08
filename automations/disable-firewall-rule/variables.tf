variable "organization-id" {
  type        = "string"
  description = "Organization ID."
}

variable "folder-ids" {
  type        = list(string)
  description = "Folder IDs to apply the disable firewall action"
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

variable "cscc-notifications-topic" {
  type = "string"
}
