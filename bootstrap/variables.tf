variable "project" {
  description = "Prefix for every resource; must match envs/*/terraform.tfvars."
  type        = string
  default     = "guardrails"
}

variable "account_id" {
  description = "Your 12-digit AWS account ID."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

variable "region" {
  description = "Region for the state bucket."
  type        = string
  default     = "us-east-1"
}

variable "allowed_regions" {
  description = "Regions the CI roles may act in."
  type        = list(string)
  default     = ["us-east-1", "us-west-2"]
}

variable "github_repo" {
  description = "owner/repo allowed to assume the CI roles."
  type        = string
  default     = "JSR-codes/terraform-policy-guardrails"

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repo))
    error_message = "github_repo must look like owner/repo, with no wildcards."
  }
}

variable "create_github_oidc_provider" {
  description = "Set false if this AWS account already has the GitHub OIDC provider."
  type        = bool
  default     = true
}

variable "owner" {
  description = "Owner tag."
  type        = string
  default     = "platform-team"
}

variable "cost_center" {
  description = "CostCenter tag."
  type        = string
  default     = "cc-1001"
}
