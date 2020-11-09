variable "automation-project" {
  type        = string
  description = "Project ID where the Cloud Functions should be installed."
}

variable "findings-project" {
  type        = string
  description = "Project ID where security findings are sent to."
}

variable "organization-id" {
  type        = string
  description = "Organization ID."
}

variable "cscc-notifications-topic-prefix" {
  type = string
}

variable "enable-scc-notification" {
  type        = bool
  description = "If true, create the notification config from SCC instead of Cloud Logging"
  default     = false
}

variable "region" {
  type = string
}

variable "findings-topic" {
  type        = string
  description = "Topic name that will receive findings JSON messages from SCC"
}

variable "notification-name" {
  type    = string
  default = "sra-notifications"
}
