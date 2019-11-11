variable "setup" {}

variable "folder-ids" {
  type        = list(string)
  description = "Remove public users from buckets if they are within the given folder IDs."
}

variable "mode" {
  type        = string
  description = "Operation mode of the cloud fucntion. One of 'ON', 'OFF' or 'DRY-RUN'."
}
