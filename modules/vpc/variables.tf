variable "name" {
  description = "Name prefix for the VPC and its resources."
  type        = string
}

variable "cidr_block" {
  description = "VPC CIDR. Must be a /16 so the subnet maths works."
  type        = string

  validation {
    condition     = can(cidrhost(var.cidr_block, 0)) && endswith(var.cidr_block, "/16")
    error_message = "cidr_block must be a valid /16, e.g. 10.10.0.0/16."
  }
}

variable "azs" {
  description = "Availability Zone names, one private and one public subnet each. Explicit names keep the layout stable."
  type        = list(string)

  validation {
    condition     = length(var.azs) >= 1 && length(var.azs) <= 6 && length(distinct(var.azs)) == length(var.azs)
    error_message = "Provide 1-6 distinct Availability Zones."
  }
}

variable "enable_nat_gateway" {
  description = "Create one NAT gateway for private subnet egress (~$32/month)."
  type        = bool
  default     = false
}

variable "permissions_boundary_arn" {
  description = "Permissions boundary for the flow-logs IAM role."
  type        = string
}

variable "flow_log_kms_key_arn" {
  description = "KMS key used to encrypt the flow-log group. The key policy must allow logs.<region>.amazonaws.com."
  type        = string
}

variable "flow_log_retention_days" {
  description = "How long to keep flow logs."
  type        = number
  default     = 365

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653], var.flow_log_retention_days)
    error_message = "flow_log_retention_days must be a value CloudWatch Logs supports."
  }
}

variable "flow_log_traffic_type" {
  description = "ACCEPT, REJECT or ALL."
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ACCEPT", "REJECT", "ALL"], var.flow_log_traffic_type)
    error_message = "flow_log_traffic_type must be ACCEPT, REJECT or ALL."
  }
}

variable "tags" {
  description = "Extra tags merged with the provider default tags."
  type        = map(string)
  default     = {}
}
