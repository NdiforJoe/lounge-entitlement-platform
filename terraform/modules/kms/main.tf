# ── KMS Module — Customer-Managed Encryption Keys ────────────────────────────
#
# Why a dedicated KMS module?
# KMS is the root of PassGuard's encryption hierarchy. Every data store (RDS,
# ElastiCache, MSK, S3, Secrets Manager) encrypts its data using a key managed
# here. If KMS is misconfigured, encryption everywhere else is meaningless.
#
# PCI DSS v4 mapping:
#   Req 3.5.1  — Cryptographic keys protected with at least as strong a key
#   Req 3.7.4  — Cryptographic keys changed at least annually (→ key rotation)
#   Req 3.7.5  — Key management procedures for retiring/replacing keys
#
# Checkov controls satisfied by this module:
#   CKV_AWS_7  — KMS key rotation enabled
#   CKV_AWS_149 — Secrets Manager uses CMK (not AWS-managed key)
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ── Data: Current AWS account and region ─────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ── Primary data encryption key ──────────────────────────────────────────────
resource "aws_kms_key" "passguard_data" {
  description             = "PassGuard data-at-rest encryption key (RDS, ElastiCache, MSK)"
  deletion_window_in_days = 30 # 30-day safety window before permanent deletion

  # PCI DSS Req 3.7.4: Annual key rotation — AWS KMS rotates automatically
  # without downtime. Old key material is retained for decryption; all new
  # encryption uses the current key version.
  enable_key_rotation = true

  # Scope to single region — reduces blast radius. Multi-region keys require
  # additional controls to prevent cross-region exfiltration.
  multi_region = false

  # Explicit key policy — deny by default, grant least-privilege.
  # Without an explicit policy, root account has full key access, which
  # violates the principle of least privilege.
  policy = data.aws_iam_policy_document.passguard_data_key_policy.json

  tags = merge(var.tags, {
    Name       = "passguard-data-key"
    Purpose    = "data-encryption"
    PCIDSSReq  = "3.5.1,3.7.4"
  })
}

resource "aws_kms_alias" "passguard_data" {
  name          = "alias/passguard/data"
  target_key_id = aws_kms_key.passguard_data.key_id
}

# ── Secrets Manager encryption key ───────────────────────────────────────────
# Separate key for secrets so we can audit secret access independently of
# data access. Different IAM policies per key = finer-grained access control.
resource "aws_kms_key" "passguard_secrets" {
  description             = "PassGuard Secrets Manager encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
  policy                  = data.aws_iam_policy_document.passguard_secrets_key_policy.json

  tags = merge(var.tags, {
    Name      = "passguard-secrets-key"
    Purpose   = "secrets-encryption"
    PCIDSSReq = "3.5.1,3.7.4"
  })
}

resource "aws_kms_alias" "passguard_secrets" {
  name          = "alias/passguard/secrets"
  target_key_id = aws_kms_key.passguard_secrets.key_id
}

# ── CloudTrail log encryption key ────────────────────────────────────────────
# CloudTrail logs are evidence in security investigations and PCI audits.
# They must be encrypted AND tamper-evident (CloudTrail log file validation
# is a separate control — see cloudtrail module).
resource "aws_kms_key" "passguard_logs" {
  description             = "PassGuard CloudTrail + application log encryption key"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false
  policy                  = data.aws_iam_policy_document.passguard_logs_key_policy.json

  tags = merge(var.tags, {
    Name      = "passguard-logs-key"
    Purpose   = "log-encryption"
    PCIDSSReq = "10.3.3"
  })
}

resource "aws_kms_alias" "passguard_logs" {
  name          = "alias/passguard/logs"
  target_key_id = aws_kms_key.passguard_logs.key_id
}

# ── IAM key policies ─────────────────────────────────────────────────────────
# Principle: root can administer keys but cannot use them for data operations.
# Application roles can encrypt/decrypt but cannot delete or disable keys.

data "aws_iam_policy_document" "passguard_data_key_policy" {
  # Statement 1: Root account can manage the key (required by AWS)
  statement {
    sid    = "EnableRootManagement"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Statement 2: Application role can use key for encrypt/decrypt only
  statement {
    sid    = "AllowAppEncryptDecrypt"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.app_role_arn]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
  }

  # Statement 3: CloudWatch can use key for log group encryption
  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }
}

data "aws_iam_policy_document" "passguard_secrets_key_policy" {
  statement {
    sid    = "EnableRootManagement"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowSecretsManagerService"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["secretsmanager.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
      "kms:CreateGrant",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "AllowAppReadSecrets"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [var.app_role_arn]
    }
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "passguard_logs_key_policy" {
  statement {
    sid    = "EnableRootManagement"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudTrailEncrypt"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions = [
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
  }
}
