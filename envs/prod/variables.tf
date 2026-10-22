variable "project" {
  description = "Short project name used as a prefix."
  type        = string
}

variable "environment" {
  description = "Environment name; must match this directory."
  type        = string
}

variable "account_id" {
  description = "AWS account ID."
  type        = string
}

variable "region" {
  description = "Region to deploy to."
  type        = string
}

variable "allowed_regions" {
  description = "Regions workloads may call."
  type        = list(string)
}

variable "vpc_cidr" {
  description = "VPC CIDR (/16)."
  type        = string
}

variable "azs" {
  description = "Availability Zones."
  type        = list(string)
}

variable "enable_nat_gateway" {
  description = "Create a NAT gateway."
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
  description = "Allow HTTPS from the internet to the app tier."
  type        = bool
  default     = false
}

variable "owner" {
  description = "Team or person accountable for these resources."
  type        = string
}

variable "cost_center" {
  description = "Cost center for billing reports."
  type        = string
}

variable "repository" {
  description = "Repository that manages this stack."
  type        = string
}
