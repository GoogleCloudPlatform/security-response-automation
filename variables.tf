variable "automation-project" {
  type        = string
  description = "Project ID where the Cloud Functions should be installed."
}

variable "findings-project" {
  type        = string
  description = "Project ID where Event Threat Detection security findings are sent to by the Security Command Center. Configured in the Google Cloud Console in Security > Threat Detection."
}

variable "organization-id" {
  type        = string
  description = "Organization ID."
}

variable "folder-ids" {
  type        = list(string)
  description = "Folder IDs to apply automations to."
}

variable "enable-scc-notification" {
  type        = bool
  description = "If true, create the notification config from SCC instead of Cloud Logging"
}
