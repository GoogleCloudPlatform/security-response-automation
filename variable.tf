variable "automation-project" {
  type        = "string"
  description = "Project ID where the Cloud Functions should be installed."
}

variable "findings-project" {
  type        = "string"
  description = "Project ID where security findings are sent to."
}

variable "revoke-within-folder" {
  type        = "string"
  description = "Folder ID where to apply Folder Admin role to enable IAM revoking within."
}

variable "organization-id" {
  type        = "string"
  description = "Organization ID."
}

variable "golang-runtime" {
  type        = "string"
  default = "go111"
}

