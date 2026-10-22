variable "name" {
  description = "Role name."
  type        = string

  validation {
    condition     = can(regex("^[\\w+=,.@-]{1,64}$", var.name))
    error_message = "Role names are 1-64 characters: letters, digits and +=,.@_-"
  }
}

variable "description" {
  description = "What the role is for."
  type        = string
}

variable "trusted_services" {
  description = "AWS service principals allowed to assume the role, e.g. ecs-tasks.amazonaws.com."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for s in var.trusted_services : endswith(s, ".amazonaws.com")])
    error_message = "Service principals must end in .amazonaws.com."
  }
}

variable "trusted_role_arns" {
  description = "IAM role ARNs allowed to assume this role. Wildcards are not accepted."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for a in var.trusted_role_arns : startswith(a, "arn:aws:iam::") && !strcontains(a, "*")])
    error_message = "trusted_role_arns must be exact IAM ARNs with no wildcards."
  }
}

variable "oidc_trust" {
  description = "Optional OIDC federation trust, e.g. GitHub Actions. Subjects must be specific, never a bare wildcard."
  type = object({
    provider_arn  = string
    provider_host = string
    audience      = string
    subjects      = list(string)
  })
  default = null

  validation {
    condition = var.oidc_trust == null ? true : (
      length(var.oidc_trust.subjects) > 0 &&
      alltrue([for s in var.oidc_trust.subjects : !contains(["*", "repo:*"], s) && !startswith(s, "*")])
    )
    error_message = "oidc_trust.subjects must list specific subjects, e.g. repo:owner/name:environment:prod."
  }
}

variable "permissions_boundary_arn" {
  description = "Required. Caps what this role can ever do, whatever policies get attached later."
  type        = string

  validation {
    condition     = startswith(var.permissions_boundary_arn, "arn:aws:iam::")
    error_message = "permissions_boundary_arn must be an IAM policy ARN."
  }
}

variable "managed_policy_arns" {
  description = "Managed policies to attach."
  type        = list(string)
  default     = []
}

variable "inline_policies" {
  description = "Inline policies as name => JSON document."
  type        = map(string)
  default     = {}
}

variable "max_session_duration" {
  description = "Maximum session length in seconds (1-12 hours)."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_duration >= 3600 && var.max_session_duration <= 43200
    error_message = "max_session_duration must be between 3600 and 43200."
  }
}

variable "tags" {
  description = "Extra tags merged with the provider default tags."
  type        = map(string)
  default     = {}
}
