variable "project" {
  description = "Short project name used as a prefix."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,20}$", var.project))
    error_message = "project must be 2-21 lowercase letters, digits or hyphens."
  }
}

variable "environment" {
  description = "dev, staging or prod."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "account_id" {
  description = "AWS account ID. Used in key policies and to make bucket names unique."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be 12 digits."
  }
}

variable "region" {
  description = "Region the stack is deployed to."
  type        = string
}

variable "allowed_regions" {
  description = "Regions workloads may call; everything else is denied by the permissions boundary."
  type        = list(string)
}

variable "vpc_cidr" {
  description = "VPC CIDR (/16)."
  type        = string
}

variable "azs" {
  description = "Availability Zones to spread subnets across."
  type        = list(string)
}

variable "enable_nat_gateway" {
  description = "Create a NAT gateway (~$32/month)."
  type        = bool
  default     = false
}

variable "kms_deletion_window_days" {
  description = "Days before a scheduled key deletion completes."
  type        = number
  default     = 30
}

variable "flow_log_retention_days" {
  description = "VPC flow-log retention."
  type        = number
  default     = 365
}

variable "public_https_ingress" {
  description = "Allow HTTPS from the internet to the app tier. False limits it to the VPC."
  type        = bool
  default     = false
}
