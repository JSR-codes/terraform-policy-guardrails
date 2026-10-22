mock_provider "aws" {}

variables {
  name        = "unit-sg"
  description = "Unit test security group"
  vpc_id      = "vpc-00000000"
  ingress_rules = [{
    description = "HTTPS from anywhere"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_ipv4   = "0.0.0.0/0"
  }]
}

run "creates_rules_from_lists" {
  command = plan

  assert {
    condition     = length(aws_vpc_security_group_ingress_rule.this) == 1
    error_message = "Expected one ingress rule."
  }

  assert {
    condition     = aws_vpc_security_group_egress_rule.this["tcp-443-443-0.0.0.0/0"].to_port == 443
    error_message = "Default egress should be HTTPS only."
  }
}

run "rejects_all_protocol_ingress" {
  command = plan

  variables {
    ingress_rules = [{
      description = "everything"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      cidr_ipv4   = "10.0.0.0/8"
    }]
  }

  expect_failures = [var.ingress_rules]
}

run "rejects_lazy_description" {
  command = plan

  variables {
    description = "sg"
  }

  expect_failures = [var.description]
}
