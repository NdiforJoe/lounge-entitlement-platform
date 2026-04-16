output "trail_arn" {
  description = "ARN of the CloudTrail trail"
  value       = aws_cloudtrail.passguard.arn
}

output "log_bucket_id" {
  description = "S3 bucket ID storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.id
}

output "log_bucket_arn" {
  description = "S3 bucket ARN storing CloudTrail logs"
  value       = aws_s3_bucket.cloudtrail_logs.arn
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch Log Group name for real-time CloudTrail streaming"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}
