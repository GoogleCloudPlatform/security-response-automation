variable "setup" {}

variable "folder-ids" {
  type        = list(string)
  description = "Remove public users from buckets if they are within the given folder IDs."
}
