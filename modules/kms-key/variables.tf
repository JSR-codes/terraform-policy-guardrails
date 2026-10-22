variable "alias" {
  description = "Alias without the alias/ prefix, e.g. acme-dev-data."
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9/_-]{1,250}$", var.alias)) && !startswith(var.alias, "aws/")
    error_message = "Alias may contain letters, digits, /, _ and -, and must not start with aws/."
  }
}

variable "description" {
  description = "What the key protects."
  type        = string
}

variable "account_id" {
  description = "AWS account that owns the key."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a 12-digit AWS account ID."
  }
}

variable "admin_role_arns" {
  description = "IAM principals allowed to administer (but not use) the key."
  type        = list(string)
  default     = []
}

variable "user_role_arns" {
  description = "IAM principals allowed to encrypt and decrypt with the key."
  type        = list(string)
  default     = []
}

variable "service_principals" {
  description = "AWS service principals allowed to use the key, e.g. logs.us-east-1.amazonaws.com."
  type        = list(string)
  default     = []
}

variable "deletion_window_in_days" {
  description = "Waiting period before a scheduled key deletion completes."
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_in_days >= 7 && var.deletion_window_in_days <= 30
    error_message = "deletion_window_in_days must be between 7 and 30."
  }
}

variable "rotation_period_in_days" {
  description = "Automatic key rotation period."
  type        = number
  default     = 365

  validation {
    condition     = var.rotation_period_in_days >= 90 && var.rotation_period_in_days <= 2560
    error_message = "rotation_period_in_days must be between 90 and 2560."
  }
}

variable "tags" {
  description = "Extra tags merged with the provider default tags."
  type        = map(string)
  default     = {}
}
