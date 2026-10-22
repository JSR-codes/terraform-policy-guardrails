output "vpc_id" {
  description = "VPC ID."
  value       = module.vpc.vpc_id
}

output "private_subnet_ids" {
  description = "Private subnet IDs."
  value       = module.vpc.private_subnet_ids
}

output "public_subnet_ids" {
  description = "Public subnet IDs."
  value       = module.vpc.public_subnet_ids
}

output "kms_key_arn" {
  description = "Environment KMS key."
  value       = module.kms.key_arn
}

output "data_bucket" {
  description = "Application data bucket."
  value       = module.data_bucket.bucket_id
}

output "app_role_arn" {
  description = "Runtime role for the application."
  value       = module.app_role.role_arn
}

output "app_security_group_id" {
  description = "Application security group."
  value       = module.app_sg.security_group_id
}

output "permissions_boundary_arn" {
  description = "Boundary every role in this environment must carry."
  value       = aws_iam_policy.boundary.arn
}
