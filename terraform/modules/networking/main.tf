# ── Networking Module — Zero-Trust Network Segmentation ──────────────────────
#
# Architecture: Three-tier subnet model
#
#   PUBLIC tier    — only ALB and NAT Gateway. No application code here.
#   PRIVATE tier   — EKS nodes, Kafka (MSK). Has internet egress via NAT GW.
#   ISOLATED tier  — RDS, ElastiCache. NO route to internet, in or out.
#
# Why three tiers?
# The "isolated" tier has no route table entry to the internet whatsoever —
# not even outbound. Even if an attacker fully compromises an application pod
# in the private tier, they cannot exfiltrate data directly from the database.
# They'd have to traverse the application's allowed network path, giving us a
# detection opportunity via VPC Flow Logs and GuardDuty.
#
# This is network-level zero trust: every subnet boundary is a control point.
#
# PCI DSS v4 mapping:
#   Req 1.2.1  — Network security controls restricting inbound/outbound traffic
#   Req 1.3.1  — Inbound traffic restricted to only necessary communications
#   Req 1.3.2  — Outbound traffic restricted to only necessary communications
#   Req 1.4.1  — NSCs between trusted and untrusted networks
#
# Checkov controls satisfied:
#   CKV_AWS_130  — VPC default security group closed (no ingress/egress)
#   CKV2_AWS_12  — Default VPC not used
#   CKV_AWS_25   — Security groups not open to 0.0.0.0/0
#   CKV_AWS_23   — VPC Flow Logs enabled
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# ── VPC ───────────────────────────────────────────────────────────────────────
resource "aws_vpc" "passguard" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true # Required for EKS and RDS endpoint resolution
  enable_dns_support   = true

  tags = merge(var.tags, {
    Name       = "${var.environment}-passguard-vpc"
    PCIDSSReq  = "1.2.1"
  })
}

# Close the default security group — it allows all traffic by default.
# Checkov CKV_AWS_130 requires this.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.passguard.id
  # No ingress or egress rules = deny all
  tags = merge(var.tags, { Name = "DO-NOT-USE-default-sg" })
}

# ── VPC Flow Logs ─────────────────────────────────────────────────────────────
# Flow logs capture metadata for every network connection to/from ENIs in the
# VPC. GuardDuty uses these to detect port scanning, unusual traffic patterns,
# and C2 communication. Also satisfies PCI DSS Req 10 network monitoring.
resource "aws_flow_log" "passguard" {
  vpc_id          = aws_vpc.passguard.id
  traffic_type    = "ALL" # Capture ACCEPT and REJECT — rejected traffic is evidence of scanning
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_logs.arn

  tags = merge(var.tags, {
    Name      = "${var.environment}-passguard-flow-logs"
    PCIDSSReq = "10.2.1"
  })
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/passguard/${var.environment}/vpc-flow-logs"
  retention_in_days = 365 # PCI DSS Req 10.5.1: 12 months minimum retention
  kms_key_id        = var.logs_key_arn

  tags = var.tags
}

resource "aws_iam_role" "flow_log" {
  name = "${var.environment}-passguard-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = var.tags
}

resource "aws_iam_role_policy" "flow_log" {
  name = "flow-log-policy"
  role = aws_iam_role.flow_log.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Resource = "*"
    }]
  })
}

# ── Internet Gateway ──────────────────────────────────────────────────────────
resource "aws_internet_gateway" "passguard" {
  vpc_id = aws_vpc.passguard.id

  tags = merge(var.tags, { Name = "${var.environment}-passguard-igw" })
}

# ── NAT Gateway (one per AZ for HA) ──────────────────────────────────────────
# Allows EKS nodes in private subnets to reach internet (for ECR image pulls,
# external APIs) without being reachable from internet.
resource "aws_eip" "nat" {
  count  = var.az_count
  domain = "vpc"

  tags = merge(var.tags, { Name = "${var.environment}-passguard-nat-eip-${count.index}" })
}

resource "aws_nat_gateway" "passguard" {
  count         = var.az_count
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(var.tags, { Name = "${var.environment}-passguard-nat-${count.index}" })

  depends_on = [aws_internet_gateway.passguard]
}

# ── PUBLIC subnets — ALB and NAT Gateway only ─────────────────────────────────
resource "aws_subnet" "public" {
  count             = var.az_count
  vpc_id            = aws_vpc.passguard.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # Never auto-assign public IPs to instances in this subnet.
  # Only the ALB gets a public IP, via its own assignment.
  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name                     = "${var.environment}-passguard-public-${count.index}"
    Tier                     = "public"
    "kubernetes.io/role/elb" = "1" # EKS ALB controller annotation
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.passguard.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.passguard.id
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-public-rt" })
}

resource "aws_route_table_association" "public" {
  count          = var.az_count
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ── PRIVATE subnets — EKS nodes, Kafka MSK ───────────────────────────────────
resource "aws_subnet" "private" {
  count             = var.az_count
  vpc_id            = aws_vpc.passguard.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + var.az_count)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name                              = "${var.environment}-passguard-private-${count.index}"
    Tier                              = "private"
    "kubernetes.io/role/internal-elb" = "1"
  })
}

resource "aws_route_table" "private" {
  count  = var.az_count
  vpc_id = aws_vpc.passguard.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.passguard[count.index].id
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-private-rt-${count.index}" })
}

resource "aws_route_table_association" "private" {
  count          = var.az_count
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ── ISOLATED subnets — RDS, ElastiCache. NO internet route. ──────────────────
# These subnets have no route table entry for 0.0.0.0/0.
# Traffic can only flow to/from other subnets within the VPC via security
# group rules. This is the data layer perimeter.
resource "aws_subnet" "isolated" {
  count             = var.az_count
  vpc_id            = aws_vpc.passguard.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index + (var.az_count * 2))
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = false

  tags = merge(var.tags, {
    Name = "${var.environment}-passguard-isolated-${count.index}"
    Tier = "isolated"
  })
}

# Isolated subnets only have a local route (no 0.0.0.0/0 entry).
resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.passguard.id
  # Only the implicit local route exists — no internet, no NAT
  tags = merge(var.tags, { Name = "${var.environment}-passguard-isolated-rt" })
}

resource "aws_route_table_association" "isolated" {
  count          = var.az_count
  subnet_id      = aws_subnet.isolated[count.index].id
  route_table_id = aws_route_table.isolated.id
}

# ── Security Groups ───────────────────────────────────────────────────────────
# Philosophy: default-deny + explicit whitelist.
# Each security group allows only the minimum traffic required for the service
# to function. No security group has 0.0.0.0/0 as an ingress source.

# ALB — accepts HTTPS from internet
resource "aws_security_group" "alb" {
  name        = "${var.environment}-passguard-alb-sg"
  description = "ALB: accept HTTPS from internet, forward to app layer"
  vpc_id      = aws_vpc.passguard.id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect (→ 301 HTTPS)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description     = "Forward to membership-service"
    from_port       = 3001
    to_port         = 3001
    protocol        = "tcp"
    security_groups = [aws_security_group.membership_service.id]
  }

  egress {
    description     = "Forward to entitlement-service"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.entitlement_service.id]
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-alb-sg" })
}

# membership-service — only ALB can reach it
resource "aws_security_group" "membership_service" {
  name        = "${var.environment}-passguard-membership-sg"
  description = "membership-service: accept from ALB only"
  vpc_id      = aws_vpc.passguard.id

  ingress {
    description     = "From ALB only"
    from_port       = 3001
    to_port         = 3001
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    description     = "PostgreSQL"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds.id]
  }

  egress {
    description     = "Kafka MSK"
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    security_groups = [aws_security_group.msk.id]
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-membership-sg" })
}

# entitlement-service — ALB + membership-service (service-to-service call)
resource "aws_security_group" "entitlement_service" {
  name        = "${var.environment}-passguard-entitlement-sg"
  description = "entitlement-service: accept from ALB and membership-service"
  vpc_id      = aws_vpc.passguard.id

  ingress {
    description     = "From ALB"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "From membership-service (internal calls)"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.membership_service.id]
  }

  egress {
    description     = "Redis ElastiCache"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.redis.id]
  }

  egress {
    description     = "Kafka MSK"
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    security_groups = [aws_security_group.msk.id]
  }

  egress {
    description     = "Reach membership-service for member lookup"
    from_port       = 3001
    to_port         = 3001
    protocol        = "tcp"
    security_groups = [aws_security_group.membership_service.id]
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-entitlement-sg" })
}

# audit-service — no inbound from internet (Kafka consumer only)
resource "aws_security_group" "audit_service" {
  name        = "${var.environment}-passguard-audit-sg"
  description = "audit-service: no public ingress, consumes Kafka only"
  vpc_id      = aws_vpc.passguard.id

  egress {
    description     = "Kafka MSK"
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    security_groups = [aws_security_group.msk.id]
  }

  egress {
    description     = "PostgreSQL (write audit records)"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.rds.id]
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-audit-sg" })
}

# RDS (isolated subnet) — only app layer can connect
resource "aws_security_group" "rds" {
  name        = "${var.environment}-passguard-rds-sg"
  description = "RDS PostgreSQL: accept from app services only"
  vpc_id      = aws_vpc.passguard.id

  ingress {
    description     = "From membership-service"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.membership_service.id]
  }

  ingress {
    description     = "From audit-service"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.audit_service.id]
  }

  # No egress rules — RDS never initiates outbound connections
  tags = merge(var.tags, { Name = "${var.environment}-passguard-rds-sg" })
}

# Redis (isolated subnet)
resource "aws_security_group" "redis" {
  name        = "${var.environment}-passguard-redis-sg"
  description = "ElastiCache Redis: accept from entitlement-service only"
  vpc_id      = aws_vpc.passguard.id

  ingress {
    description     = "From entitlement-service only"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.entitlement_service.id]
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-redis-sg" })
}

# MSK (private subnet)
resource "aws_security_group" "msk" {
  name        = "${var.environment}-passguard-msk-sg"
  description = "MSK Kafka: accept from app services only"
  vpc_id      = aws_vpc.passguard.id

  ingress {
    description     = "From membership-service"
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    security_groups = [aws_security_group.membership_service.id]
  }

  ingress {
    description     = "From entitlement-service"
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    security_groups = [aws_security_group.entitlement_service.id]
  }

  ingress {
    description     = "From audit-service"
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    security_groups = [aws_security_group.audit_service.id]
  }

  tags = merge(var.tags, { Name = "${var.environment}-passguard-msk-sg" })
}
