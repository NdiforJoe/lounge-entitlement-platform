# ── Detective Controls Module — Runtime Threat Detection ─────────────────────
#
# What detective controls do:
# Preventive controls (firewalls, encryption, rate limiting) try to stop
# attacks before they succeed. Detective controls assume some attacks WILL get
# through — they detect, alert, and enable rapid response.
#
# The three services in this module:
#
# 1. GuardDuty — ML-based threat detection
#    Analyses VPC Flow Logs, DNS query logs, and CloudTrail to detect:
#    - Crypto mining (unusual outbound connections to known mining pools)
#    - Credential theft (tokens used from unusual locations/times)
#    - Port scanning (host reconnaissance patterns in flow logs)
#    - C2 communication (traffic to known malicious IPs/domains)
#    - Privilege escalation (unusual IAM API call patterns)
#
# 2. Security Hub — Centralised findings aggregation
#    Aggregates findings from GuardDuty, Inspector, Macie, and Checkov.
#    Also runs PCI DSS v3.2.1 standard checks continuously (~150 controls).
#    If any control drifts out of compliance, Security Hub raises a finding
#    within minutes — not at the next annual audit.
#
# 3. AWS Config — Continuous compliance monitoring
#    Records configuration state of every AWS resource.
#    Evaluates against Config Rules (e.g., "all S3 buckets must be encrypted").
#    If a developer accidentally makes a bucket public, Config detects it
#    in ~3 minutes and can auto-remediate (Lambda function to re-block access).
#
# PCI DSS v4 mapping:
#   Req 10.7   — Detect and respond to failures of critical security controls
#   Req 11.5   — Intrusion detection and prevention
#   Req 12.3.2 — Targeted risk analysis for each control
#
# Checkov controls satisfied:
#   CKV_AWS_86  — GuardDuty enabled
#   CKV_AWS_150 — Security Hub enabled
#   CKV2_AWS_48 — Security Hub auto-enable for new accounts
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

# ── GuardDuty ─────────────────────────────────────────────────────────────────
resource "aws_guardduty_detector" "passguard" {
  enable = true

  datasources {
    # S3 data events: detect unusual access patterns (bulk downloads, access
    # from unexpected IPs, access to sensitive prefixes)
    s3_logs {
      enable = true
    }

    # EKS audit log analysis: detect container escape attempts, privilege
    # escalation within the cluster, unusual API server calls
    kubernetes {
      audit_logs {
        enable = true
      }
    }

    # Malware protection: scan EBS volumes of instances flagged by GuardDuty
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  # 15-minute frequency for CloudWatch events (lowest latency for alerts)
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  tags = merge(var.tags, {
    Name      = "${var.environment}-passguard-guardduty"
    PCIDSSReq = "11.5"
  })
}

# ── Security Hub ──────────────────────────────────────────────────────────────
resource "aws_securityhub_account" "passguard" {
  # Auto-enable for new member accounts (important in multi-account orgs)
  auto_enable_controls = true

  # Enable new controls as AWS releases them automatically
  control_finding_generator = "SECURITY_CONTROL"
}

# PCI DSS v3.2.1 standard — ~150 automated checks across the account
# Checks examples:
#   PCI.CloudTrail.1 — CloudTrail enabled and logging
#   PCI.IAM.4        — Hardware MFA enabled for root
#   PCI.S3.2         — S3 buckets prohibit public read access
#   PCI.KMS.1        — KMS CMK rotation enabled
#   PCI.RDS.1        — RDS snapshots not publicly available
resource "aws_securityhub_standards_subscription" "pci_dss" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/pci-dss/v/3.2.1"
  depends_on    = [aws_securityhub_account.passguard]
}

# CIS AWS Foundations Benchmark — general AWS hardening baseline
resource "aws_securityhub_standards_subscription" "cis" {
  standards_arn = "arn:aws:securityhub:${data.aws_region.current.name}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.passguard]
}

# Connect GuardDuty findings to Security Hub for unified view
resource "aws_securityhub_finding_aggregator" "passguard" {
  linking_mode = "ALL_REGIONS"
  depends_on   = [aws_securityhub_account.passguard]
}

# ── AWS Config ────────────────────────────────────────────────────────────────
# IAM role for Config service
resource "aws_iam_role" "config" {
  name = "${var.environment}-passguard-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Dedicated access log bucket for Config snapshots (CKV_AWS_18)
# This bucket IS the log target — enabling access logging on it would create
# a circular dependency, so CKV_AWS_18 is skipped here only.
#checkov:skip=CKV_AWS_18:This bucket is the access log target for config_snapshots — circular dependency if enabled
resource "aws_s3_bucket" "config_access_logs" {
  bucket        = "${var.environment}-passguard-config-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, { Name = "${var.environment}-passguard-config-access-logs" })
}

resource "aws_s3_bucket_public_access_block" "config_access_logs" {
  bucket                  = aws_s3_bucket.config_access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_access_logs" {
  bucket = aws_s3_bucket.config_access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_key_arn
    }
  }
}

# S3 bucket for Config snapshots
resource "aws_s3_bucket" "config_snapshots" {
  bucket        = "${var.environment}-passguard-config-${data.aws_caller_identity.current.account_id}"
  force_destroy = false

  tags = merge(var.tags, { Name = "${var.environment}-passguard-config-snapshots" })
}

resource "aws_s3_bucket_public_access_block" "config_snapshots" {
  bucket                  = aws_s3_bucket.config_snapshots.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config_snapshots" {
  bucket = aws_s3_bucket.config_snapshots.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.logs_key_arn
    }
  }
}

resource "aws_s3_bucket_versioning" "config_snapshots" {
  bucket = aws_s3_bucket.config_snapshots.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_logging" "config_snapshots" {
  bucket        = aws_s3_bucket.config_snapshots.id
  target_bucket = aws_s3_bucket.config_access_logs.id
  target_prefix = "config-snapshots/"
}

resource "aws_s3_bucket_policy" "config_snapshots" {
  bucket = aws_s3_bucket.config_snapshots.id
  policy = data.aws_iam_policy_document.config_bucket_policy.json
}

data "aws_iam_policy_document" "config_bucket_policy" {
  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_snapshots.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config_snapshots.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid    = "DenyHTTP"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config_snapshots.arn, "${aws_s3_bucket.config_snapshots.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

# Config recorder — track ALL resource types
resource "aws_config_configuration_recorder" "passguard" {
  name     = "${var.environment}-passguard-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true # Track IAM resources
  }
}

# Delivery channel — where Config sends snapshots
resource "aws_config_delivery_channel" "passguard" {
  name           = "${var.environment}-passguard-config-delivery"
  s3_bucket_name = aws_s3_bucket.config_snapshots.id

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }

  depends_on = [aws_config_configuration_recorder.passguard]
}

resource "aws_config_configuration_recorder_status" "passguard" {
  name       = aws_config_configuration_recorder.passguard.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.passguard]
}

# ── Config Rules — PCI DSS Specific ──────────────────────────────────────────
# These rules run continuously and flag non-compliant resources immediately.

# KMS key rotation must be enabled (PCI DSS Req 3.7.4)
resource "aws_config_config_rule" "kms_rotation" {
  name        = "${var.environment}-passguard-kms-key-rotation"
  description = "PCI DSS Req 3.7.4: KMS CMKs must have automatic rotation enabled"

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.passguard]

  tags = merge(var.tags, { PCIDSSReq = "3.7.4" })
}

# S3 buckets must block public access (PCI DSS Req 1.3.2)
resource "aws_config_config_rule" "s3_public_access" {
  name        = "${var.environment}-passguard-s3-no-public-access"
  description = "PCI DSS Req 1.3.2: S3 buckets must block all public access"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.passguard]

  tags = merge(var.tags, { PCIDSSReq = "1.3.2" })
}

# RDS encryption at rest (PCI DSS Req 3.5.1)
resource "aws_config_config_rule" "rds_encryption" {
  name        = "${var.environment}-passguard-rds-encryption"
  description = "PCI DSS Req 3.5.1: RDS instances must be encrypted at rest"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder_status.passguard]

  tags = merge(var.tags, { PCIDSSReq = "3.5.1" })
}

# MFA on root (PCI DSS Req 8.4.1)
resource "aws_config_config_rule" "root_mfa" {
  name        = "${var.environment}-passguard-root-mfa"
  description = "PCI DSS Req 8.4.1: Root account must have MFA enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.passguard]

  tags = merge(var.tags, { PCIDSSReq = "8.4.1" })
}

# CloudTrail enabled (PCI DSS Req 10.2)
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name        = "${var.environment}-passguard-cloudtrail-enabled"
  description = "PCI DSS Req 10.2: CloudTrail must be enabled in all regions"

  source {
    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.passguard]

  tags = merge(var.tags, { PCIDSSReq = "10.2" })
}
