variable "name" {
  description = "Security group name."
  type        = string
}

variable "description" {
  description = "What the group protects. Shown in the console, so make it useful."
  type        = string

  validation {
    condition     = length(trimspace(var.description)) >= 10
    error_message = "Give the security group a real description (10+ characters)."
  }
}

variable "vpc_id" {
  description = "VPC the group belongs to."
  type        = string
}

variable "ingress_rules" {
  description = "Inbound rules. Every rule needs a description so reviewers know why it exists."
  type = list(object({
    description = string
    protocol    = string
    from_port   = number
    to_port     = number
    cidr_ipv4   = string
  }))
  default = []

  validation {
    condition     = alltrue([for r in var.ingress_rules : length(trimspace(r.description)) > 0 && can(cidrhost(r.cidr_ipv4, 0))])
    error_message = "Each ingress rule needs a description and a valid IPv4 CIDR."
  }

  validation {
    condition     = alltrue([for r in var.ingress_rules : r.protocol != "-1"])
    error_message = "Inbound 'all protocols' rules are not allowed; name the protocol and ports."
  }
}

variable "egress_rules" {
  description = "Outbound rules. Defaults to HTTPS only."
  type = list(object({
    description = string
    protocol    = string
    from_port   = number
    to_port     = number
    cidr_ipv4   = string
  }))
  default = [{
    description = "HTTPS to the internet"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_ipv4   = "0.0.0.0/0"
  }]

  validation {
    condition     = alltrue([for r in var.egress_rules : length(trimspace(r.description)) > 0 && can(cidrhost(r.cidr_ipv4, 0))])
    error_message = "Each egress rule needs a description and a valid IPv4 CIDR."
  }
}

variable "tags" {
  description = "Extra tags merged with the provider default tags."
  type        = map(string)
  default     = {}
}
