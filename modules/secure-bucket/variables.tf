variable "name" {
  description = "Globally unique bucket name."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.name)) && !can(regex("\\.\\.", var.name))
    error_message = "Bucket names must be 3-63 lowercase letters, digits, dots or hyphens."
  }
}

variable "kms_key_arn" {
  description = "KMS key used for default encryption. Required: this module never falls back to S3-managed keys."
  type        = string

  validation {
    condition     = startswith(var.kms_key_arn, "arn:")
    error_message = "kms_key_arn must be a KMS key ARN."
  }
}

variable "versioning_enabled" {
  description = "Keep previous object versions so overwrites and deletes can be undone."
  type        = bool
  default     = true
}

variable "noncurrent_version_expiration_days" {
  description = "Delete old object versions after this many days."
  type        = number
  default     = 90

  validation {
    condition     = var.noncurrent_version_expiration_days >= 1
    error_message = "noncurrent_version_expiration_days must be at least 1."
  }
}

variable "force_destroy" {
  description = "Allow terraform destroy to empty a non-empty bucket. Keep false outside throwaway environments."
  type        = bool
  default     = false
}

variable "tags" {
  description = "Extra tags merged with the provider default tags."
  type        = map(string)
  default     = {}
}
