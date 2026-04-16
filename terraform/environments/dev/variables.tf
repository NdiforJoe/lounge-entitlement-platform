variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "eu-west-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "app_role_arn" {
  description = "ARN of the IAM role assumed by EKS application pods (IRSA)"
  type        = string
}

variable "sns_alert_topic_arns" {
  description = "SNS topic ARNs for security alerts (CloudWatch alarms)"
  type        = list(string)
  default     = []
}
