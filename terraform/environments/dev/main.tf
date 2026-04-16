# ── Dev Environment — PassGuard Infrastructure Entrypoint ─────────────────────
#
# This file wires together the four security modules in dependency order:
#
#   1. KMS — encryption keys (no dependencies)
#   2. Networking — VPC, subnets, security groups (depends on: KMS for flow logs)
#   3. CloudTrail — API audit logging (depends on: KMS for log encryption)
#   4. Detective Controls — GuardDuty, Security Hub, Config (depends on: KMS)
#
# In production you would add:
#   5. Data stores (RDS, ElastiCache, MSK) — depends on: KMS + Networking
#   6. EKS cluster — depends on: Networking
#   7. Application (Helm charts) — depends on: EKS + Data stores

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Remote state in S3 with DynamoDB locking (PCI DSS Req 12: change management)
  # Uncomment and configure before running terraform init in a real deployment:
  # backend "s3" {
  #   bucket         = "passguard-terraform-state-<account-id>"
  #   key            = "environments/dev/terraform.tfstate"
  #   region         = "eu-west-1"
  #   encrypt        = true
  #   kms_key_id     = "alias/passguard/terraform-state"
  #   dynamodb_table = "passguard-terraform-locks"
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

locals {
  environment = "dev"
  common_tags = {
    Project     = "passguard"
    Environment = local.environment
    ManagedBy   = "terraform"
    Compliance  = "PCI-DSS-v4"
    CostCentre  = "engineering"
  }
}

# ── Module 1: KMS — Encryption Keys ──────────────────────────────────────────
# Created first because every other module references key ARNs.
module "kms" {
  source = "../../modules/kms"

  app_role_arn = var.app_role_arn
  tags         = local.common_tags
}

# ── Module 2: Networking — VPC, Subnets, Security Groups ─────────────────────
module "networking" {
  source = "../../modules/networking"

  environment  = local.environment
  vpc_cidr     = var.vpc_cidr
  az_count     = 2
  logs_key_arn = module.kms.logs_key_arn
  tags         = local.common_tags
}

# ── Module 3: CloudTrail — Audit Logging ──────────────────────────────────────
module "cloudtrail" {
  source = "../../modules/cloudtrail"

  environment          = local.environment
  logs_key_arn         = module.kms.logs_key_arn
  sns_alert_topic_arns = var.sns_alert_topic_arns
  tags                 = local.common_tags
}

# ── Module 4: Detective Controls — GuardDuty, Security Hub, Config ────────────
module "detective_controls" {
  source = "../../modules/detective_controls"

  environment  = local.environment
  logs_key_arn = module.kms.logs_key_arn
  tags         = local.common_tags
}

# ── Outputs for downstream modules ────────────────────────────────────────────
output "vpc_id" {
  value = module.networking.vpc_id
}

output "private_subnet_ids" {
  value = module.networking.private_subnet_ids
}

output "isolated_subnet_ids" {
  value = module.networking.isolated_subnet_ids
}

output "kms_data_key_arn" {
  value     = module.kms.data_key_arn
  sensitive = true
}

output "cloudtrail_trail_arn" {
  value = module.cloudtrail.trail_arn
}
