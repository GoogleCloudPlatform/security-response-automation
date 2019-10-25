variable "setup" {}

variable "folder-ids" {
  type        = list(string)
  description = "Remove public ips from cloud sql instances if they are within the given folder IDs."
}
