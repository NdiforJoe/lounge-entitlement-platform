variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
}

variable "logs_key_arn" {
  description = "ARN of the KMS key used to encrypt CloudTrail logs and CloudWatch log group"
  type        = string
}

variable "sns_alert_topic_arns" {
  description = "List of SNS topic ARNs to notify on security alarms (PagerDuty, Slack, etc.)"
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
