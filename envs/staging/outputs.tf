output "vpc_id" {
  description = "VPC ID."
  value       = module.baseline.vpc_id
}

output "data_bucket" {
  description = "Application data bucket."
  value       = module.baseline.data_bucket
}

output "app_role_arn" {
  description = "Application runtime role."
  value       = module.baseline.app_role_arn
}

output "kms_key_arn" {
  description = "Environment KMS key."
  value       = module.baseline.kms_key_arn
}
