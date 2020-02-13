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

variable "folder-ids" {
  type        = list(string)
  description = "Folder IDs to apply automations to."
}

variable "turbinia-project-id" {
  type        = string
  description = "Project id where Turbinia is installed."
}

variable "target-project-id" {
  type        = string
  description = "Project id where snapshots disks will be created."
}
