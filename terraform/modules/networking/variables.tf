variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "az_count" {
  description = "Number of availability zones to deploy across (2 minimum for HA)"
  type        = number
  default     = 2
}

variable "logs_key_arn" {
  description = "ARN of the KMS key used to encrypt VPC Flow Log CloudWatch log group"
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
