output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.passguard.id
}

output "public_subnet_ids" {
  description = "IDs of the public subnets (ALB tier)"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets (EKS nodes, MSK)"
  value       = aws_subnet.private[*].id
}

output "isolated_subnet_ids" {
  description = "IDs of the isolated subnets (RDS, ElastiCache — no internet route)"
  value       = aws_subnet.isolated[*].id
}

output "sg_alb_id" {
  value = aws_security_group.alb.id
}

output "sg_membership_service_id" {
  value = aws_security_group.membership_service.id
}

output "sg_entitlement_service_id" {
  value = aws_security_group.entitlement_service.id
}

output "sg_audit_service_id" {
  value = aws_security_group.audit_service.id
}

output "sg_rds_id" {
  value = aws_security_group.rds.id
}

output "sg_redis_id" {
  value = aws_security_group.redis.id
}

output "sg_msk_id" {
  value = aws_security_group.msk.id
}
