terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

locals {
  # Stable keys so reordering the list doesn't recreate rules
  ingress = { for r in var.ingress_rules : "${r.protocol}-${r.from_port}-${r.to_port}-${r.cidr_ipv4}" => r }
  egress  = { for r in var.egress_rules : "${r.protocol}-${r.from_port}-${r.to_port}-${r.cidr_ipv4}" => r }
}

resource "aws_security_group" "this" {
  name        = var.name
  description = var.description
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = var.name })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "this" {
  for_each = local.ingress

  security_group_id = aws_security_group.this.id
  description       = each.value.description
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_ipv4         = each.value.cidr_ipv4
  tags              = var.tags
}

resource "aws_vpc_security_group_egress_rule" "this" {
  for_each = local.egress

  security_group_id = aws_security_group.this.id
  description       = each.value.description
  ip_protocol       = each.value.protocol
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  cidr_ipv4         = each.value.cidr_ipv4
  tags              = var.tags
}
