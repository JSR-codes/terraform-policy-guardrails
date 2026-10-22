# Generated policy JSON is random in a mock provider, so give it valid JSON.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name                     = "unit-role"
  description              = "unit test"
  trusted_services         = ["ecs-tasks.amazonaws.com"]
  permissions_boundary_arn = "arn:aws:iam::111111111111:policy/boundary"
  inline_policies = {
    read = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
  }
}

run "boundary_always_attached" {
  command = plan

  assert {
    condition     = aws_iam_role.this.permissions_boundary == var.permissions_boundary_arn
    error_message = "Every role must carry the permissions boundary."
  }

  assert {
    condition     = length(aws_iam_role_policy.inline) == 1
    error_message = "Inline policies should be created one per map entry."
  }
}

run "rejects_role_nobody_can_assume" {
  command = plan

  variables {
    trusted_services = []
  }

  expect_failures = [aws_iam_role.this]
}

run "rejects_wildcard_trust" {
  command = plan

  variables {
    trusted_role_arns = ["arn:aws:iam::*:role/*"]
  }

  expect_failures = [var.trusted_role_arns]
}

run "rejects_non_arn_boundary" {
  command = plan

  variables {
    permissions_boundary_arn = "none"
  }

  expect_failures = [var.permissions_boundary_arn]
}

run "accepts_github_oidc_trust" {
  command = plan

  variables {
    trusted_services = []
    oidc_trust = {
      provider_arn  = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
      provider_host = "token.actions.githubusercontent.com"
      audience      = "sts.amazonaws.com"
      subjects      = ["repo:octo/demo:environment:prod"]
    }
  }

  assert {
    condition     = aws_iam_role.this.name == "unit-role"
    error_message = "OIDC-only trust should be accepted."
  }
}

run "rejects_wildcard_oidc_subject" {
  command = plan

  variables {
    trusted_services = []
    oidc_trust = {
      provider_arn  = "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"
      provider_host = "token.actions.githubusercontent.com"
      audience      = "sts.amazonaws.com"
      subjects      = ["repo:*"]
    }
  }

  expect_failures = [var.oidc_trust]
}
