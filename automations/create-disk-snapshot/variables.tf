variable "organization-id" {
  type        = "string"
  description = "Organization ID."
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

variable "findings-topic" {
  type = "string"
}
