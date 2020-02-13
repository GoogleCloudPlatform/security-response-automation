variable "setup" {}

variable "folder-ids" {
  type        = list(string)
  description = "Folder IDs to grant the necessary permissions for this Cloud Function execution."
}

variable "target-project-id" {
  type        = string
  description = "Target project id to grant the necessary permissions for this Cloud Function execution."
}