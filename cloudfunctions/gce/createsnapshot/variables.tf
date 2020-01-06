variable "setup" {}

variable "folder-ids" {
  type        = list(string)
  description = "Folder IDs to grant the necessary permissions for this Cloud Function execution."
}
