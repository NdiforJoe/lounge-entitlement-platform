output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = aws_guardduty_detector.passguard.id
}

output "config_recorder_name" {
  description = "Name of the AWS Config configuration recorder"
  value       = aws_config_configuration_recorder.passguard.name
}
