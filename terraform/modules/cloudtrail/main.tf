# ── CloudTrail Module — Audit Logging of All AWS API Calls ───────────────────
#
# What CloudTrail records:
# Every API call made to AWS services — who called it, from where, with what
# parameters, and whether it succeeded. Examples:
#   - "eks:CreateCluster called by arn:aws:iam::123:user/alice at 14:23:01"
#   - "s3:GetObject called by arn:aws:iam::123:role/app-role at 14:23:02"
#   - "kms:Decrypt called by arn:aws:iam::123:role/app-role at 14:23:03"
#
# Why this matters for PCI DSS:
# Requirement 10 mandates logging and monitoring of ALL access to system
# components. CloudTrail is the AWS implementation of this requirement.
# Without it, you cannot answer "who changed this security group?" or
# "who accessed the card data at 3am?"
#
# PCI DSS v4 mapping:
#   Req 10.2.1  — Audit log capturing all individual user access
#   Req 10.2.2  — Audit log capturing all actions by root/administrators
#   Req 10.3.2  — Audit log files protected from modification (log validation)
#   Req 10.3.3  — Audit log files backed up (S3 with versioning)
#   Req 10.5.1  — Log retention: at least 12 months
#
# Checkov controls satisfied:
#   CKV_AWS_36  — CloudTrail log file validation enabled
#   CKV_AWS_35  — CloudTrail logs sent to CloudWatch
#   CKV_AWS_67  — CloudTrail multi-region enabled
#   CKV_AWS_252 — CloudTrail encrypted with CMK
#   CKV_AWS_18  — S3 bucket access logging enabled
#   CKV_AWS_19  — S3 bucket server-side encryption enabled
#   CKV_AWS_20  — S3 bucket not publicly accessible
#   CKV_AWS_21  — S3 bucket versioning enabled
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── S3 Bucket for CloudTrail logs ─────────────────────────────────────────────
resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${var.environment}-passguard-cloudtrail-${data.aws_caller_identity.current.account_id}"
  force_destroy = false # Never accidentally delete audit logs

  tags = merge(var.tags, {
    Name      = "${var.environment}-passguard-cloudtrail"
    PCIDSSReq = "10.3.3,10.5.1"
  })
}

# PCI DSS Req 10.3.2 — logs protected from modification.
# Versioning means even if someone calls DeleteObject, the version is
# recoverable. S3 Object Lock (below) provides immutability.
resource "aws_s3_bucket_versioning" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Object Lock — WORM (Write Once Read Many) protection.
# In COMPLIANCE mode, not even the root account can delete objects before
# the retention period expires. This is the strongest log protection
# available in AWS and directly satisfies PCI DSS Req 10.3.2.
resource "aws_s3_bucket_object_lock_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365 # PCI DSS Req 10.5.1: 12 months minimum
    }
  }
}

# Block all public access — audit logs must never be public
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket                  = aws_s3_bucket.cloudtrail_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Encrypt logs at rest using the CloudTrail KMS key
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_key_arn
    }
    bucket_key_enabled = true # Reduces KMS API call cost by 99%
  }
}

# S3 access logging — log who accessed the log bucket (meta-logging)
resource "aws_s3_bucket_logging" "cloudtrail_logs" {
  bucket        = aws_s3_bucket.cloudtrail_logs.id
  target_bucket = aws_s3_bucket.cloudtrail_logs.id
  target_prefix = "s3-access-logs/"
}

# S3 lifecycle — move old logs to Glacier after 90 days (cost optimisation)
# while maintaining 12-month total retention
resource "aws_s3_bucket_lifecycle_configuration" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    id     = "glacier-after-90-days"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years — exceeds PCI DSS 12-month minimum
    }
  }
}

# Bucket policy — only CloudTrail service can write; deny HTTP (require HTTPS)
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket_policy.json
}

data "aws_iam_policy_document" "cloudtrail_bucket_policy" {
  # Allow CloudTrail to check bucket ACL
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn]
  }

  # Allow CloudTrail to write log files
  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:cloudtrail:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:trail/passguard-trail"]
    }
  }

  # Deny all non-HTTPS access — prevents credentials from being transmitted
  # in plaintext. Checkov CKV_AWS_20 / PCI DSS Req 4.2.1.
  statement {
    sid    = "DenyHTTP"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.cloudtrail_logs.arn, "${aws_s3_bucket.cloudtrail_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# ── CloudWatch Log Group for real-time alerting ───────────────────────────────
# S3 is for long-term retention. CloudWatch Logs is for real-time metric
# filters and alarms (e.g., alert on root login, security group changes).
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/passguard/${var.environment}/cloudtrail"
  retention_in_days = 90 # 90 days in CW; remainder in S3 Glacier
  kms_key_id        = var.logs_key_arn

  tags = var.tags
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = "${var.environment}-passguard-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = "cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# ── CloudTrail — the actual trail ─────────────────────────────────────────────
resource "aws_cloudtrail" "passguard" {
  name           = "passguard-trail"
  s3_bucket_name = aws_s3_bucket.cloudtrail_logs.id

  # Multi-region: catches events in ALL regions, not just the primary one.
  # Attackers often use us-east-1 (the default for many services) or
  # less-monitored regions to evade detection.
  is_multi_region_trail = true

  # Global service events: captures IAM, STS, and other global service API
  # calls. Without this, IAM changes (adding admin users, creating access keys)
  # would not be logged.
  include_global_service_events = true

  # LOG FILE VALIDATION — critical PCI DSS Req 10.3.2 control.
  # CloudTrail creates a SHA-256 signed digest file every hour that contains
  # hashes of all log files delivered in that hour. You can run:
  #   aws cloudtrail validate-logs --trail-arn <arn> --start-time <time>
  # to prove logs have not been modified since creation. This is a forensic
  # integrity guarantee — essential for incident response and PCI audits.
  enable_log_file_validation = true

  # Encrypt logs with our CMK (not the default AWS-managed key).
  # This means only principals with KMS access can read the logs.
  kms_key_id = var.logs_key_arn

  # Send to CloudWatch for real-time alerting
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_cloudwatch.arn

  # Capture S3 data events (object-level operations).
  # Management events (CreateBucket, DeleteBucket) are captured by default.
  # Data events capture individual PutObject/GetObject calls — required for
  # PCI DSS Req 10.2.1 (logging all access to cardholder data environment).
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.cloudtrail_logs.arn}/"]
    }
  }

  depends_on = [
    aws_s3_bucket_policy.cloudtrail_logs
  ]

  tags = merge(var.tags, {
    Name      = "passguard-trail"
    PCIDSSReq = "10.2.1,10.3.2,10.5.1"
  })
}

# ── CloudWatch Metric Filters + Alarms ───────────────────────────────────────
# PCI DSS Req 10.6.1 — review logs daily. In practice: use alarms so you
# don't have to manually review logs — the system alerts you to critical events.

# Alarm: Root account used
resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "${var.environment}-passguard-root-login"
  alarm_description   = "CRITICAL: Root account used — PCI DSS Req 10.2.2"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.root_login.metric_transformation[0].name
  namespace           = "PassGuard/SecurityEvents"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = var.sns_alert_topic_arns
  treat_missing_data  = "notBreaching"

  tags = var.tags
}

resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "${var.environment}-passguard-root-login-filter"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "PassGuard/SecurityEvents"
    value     = "1"
  }
}

# Alarm: Unauthorised API calls (access denied)
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "${var.environment}-passguard-unauthorized-api-filter"
  pattern        = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied\") || ($.errorCode = \"*Forbidden*\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "UnauthorisedAPICalls"
    namespace = "PassGuard/SecurityEvents"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "${var.environment}-passguard-unauthorized-api"
  alarm_description   = "HIGH: Repeated unauthorised API calls detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.unauthorized_api.metric_transformation[0].name
  namespace           = "PassGuard/SecurityEvents"
  period              = 300
  statistic           = "Sum"
  threshold           = 5 # Alert after 5 denied calls in 5 minutes
  alarm_actions       = var.sns_alert_topic_arns
  treat_missing_data  = "notBreaching"

  tags = var.tags
}

# Alarm: Security group changes
resource "aws_cloudwatch_log_metric_filter" "sg_changes" {
  name           = "${var.environment}-passguard-sg-changes-filter"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = "PassGuard/SecurityEvents"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "sg_changes" {
  alarm_name          = "${var.environment}-passguard-sg-changes"
  alarm_description   = "HIGH: Security group modified — verify this is authorised"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = aws_cloudwatch_log_metric_filter.sg_changes.metric_transformation[0].name
  namespace           = "PassGuard/SecurityEvents"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = var.sns_alert_topic_arns
  treat_missing_data  = "notBreaching"

  tags = var.tags
}
