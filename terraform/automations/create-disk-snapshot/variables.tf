variable "setup" {}

variable "turbinia-project-id" {
  type        = string
  description = "Project ID where Turbinia is installed."
}

variable "turbinia-topic-name" {
  type        = string
  description = "PubSub topic where Turbinia should be notified."
}