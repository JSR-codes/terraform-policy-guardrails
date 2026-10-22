output "state_bucket" {
  description = "Put this in envs/*/backend.hcl."
  value       = module.state_bucket.bucket_id
}

output "plan_role_arn" {
  description = "GitHub secret AWS_PLAN_ROLE_ARN."
  value       = module.plan_role.role_arn
}

output "apply_role_arn" {
  description = "GitHub secret AWS_APPLY_ROLE_ARN."
  value       = module.apply_role.role_arn
}
