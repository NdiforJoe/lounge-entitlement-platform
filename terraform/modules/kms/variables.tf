variable "app_role_arn" {
  description = "ARN of the IAM role assumed by EKS application pods (IRSA)"
  type        = string
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
