# Mock values are random strings, so give JSON and ARNs valid shapes.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_cloudwatch_log_group" {
    defaults = {
      arn = "arn:aws:logs:us-east-1:111111111111:log-group:/vpc/unit/flow-logs"
    }
  }

  mock_resource "aws_iam_role" {
    defaults = {
      arn = "arn:aws:iam::111111111111:role/unit-flow-logs"
    }
  }
}

variables {
  name                     = "unit"
  cidr_block               = "10.10.0.0/16"
  azs                      = ["us-east-1a", "us-east-1b", "us-east-1c"]
  permissions_boundary_arn = "arn:aws:iam::111111111111:policy/boundary"
  flow_log_kms_key_arn     = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
}

run "one_private_and_public_subnet_per_az" {
  command = plan

  assert {
    condition     = length(aws_subnet.private) == 3 && length(aws_subnet.public) == 3
    error_message = "Expected one private and one public subnet per AZ."
  }

  assert {
    condition     = aws_subnet.private[0].cidr_block == "10.10.0.0/20" && aws_subnet.public[0].cidr_block == "10.10.240.0/24"
    error_message = "Subnet CIDRs are not where the module documents them."
  }

  assert {
    condition     = alltrue([for s in aws_subnet.public : s.map_public_ip_on_launch == false])
    error_message = "Public subnets must not auto-assign public IPs."
  }
}

run "flow_logs_on_and_encrypted" {
  command = plan

  assert {
    condition     = aws_flow_log.this.traffic_type == "ALL"
    error_message = "Flow logs should capture all traffic by default."
  }

  assert {
    condition     = aws_cloudwatch_log_group.flow_logs.kms_key_id == var.flow_log_kms_key_arn
    error_message = "Flow-log group must be KMS-encrypted."
  }

  assert {
    condition     = aws_iam_role.flow_logs.permissions_boundary == var.permissions_boundary_arn
    error_message = "Flow-log role must carry the permissions boundary."
  }
}

run "nat_off_by_default" {
  command = plan

  assert {
    condition     = length(aws_nat_gateway.this) == 0
    error_message = "NAT gateway should be opt-in."
  }
}

run "rejects_non_16_cidr" {
  command = plan

  variables {
    cidr_block = "10.10.0.0/24"
  }

  expect_failures = [var.cidr_block]
}

run "rejects_duplicate_azs" {
  command = plan

  variables {
    azs = ["us-east-1a", "us-east-1a"]
  }

  expect_failures = [var.azs]
}
