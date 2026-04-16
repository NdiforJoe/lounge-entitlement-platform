variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "logs_key_arn" {
  description = "ARN of the KMS key used to encrypt Config snapshots"
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
