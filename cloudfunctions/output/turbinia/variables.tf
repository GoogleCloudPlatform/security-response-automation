variable "setup" {}

variable "turbinia-project-id" {
  type        = string
  description = "Project ID where Turbinia is installed to grant the necessary permissions for this Cloud Function execution."
}

variable "folder-ids" {
  type        = list(string)
  description = "Folder IDs to grant the necessary permissions for this Cloud Function execution."
}
