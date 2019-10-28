variable "setup" {}

variable "folder-ids" {
  type        = list(string)
  description = "Enable data access logs only to projects inside of this folder IDs list"
}
