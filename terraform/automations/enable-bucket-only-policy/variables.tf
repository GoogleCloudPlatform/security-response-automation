variable "setup" {}

variable "folder-ids" {
  type        = list(string)
  description = "Enable Bucket only policy if the buckets are within the given folder IDs."
}

variable "mode" {
  type        = string
  description = "Operation mode of the cloud function."
}
