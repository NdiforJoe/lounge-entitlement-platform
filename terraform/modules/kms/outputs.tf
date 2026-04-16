output "data_key_arn" {
  description = "ARN of the data encryption key (for RDS, MSK, ElastiCache)"
  value       = aws_kms_key.passguard_data.arn
}

output "data_key_id" {
  description = "Key ID of the data encryption key"
  value       = aws_kms_key.passguard_data.key_id
}

output "secrets_key_arn" {
  description = "ARN of the Secrets Manager encryption key"
  value       = aws_kms_key.passguard_secrets.arn
}

output "logs_key_arn" {
  description = "ARN of the log encryption key (CloudTrail, CloudWatch)"
  value       = aws_kms_key.passguard_logs.arn
}
