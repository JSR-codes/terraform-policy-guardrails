# Generated policy JSON is random in a mock provider, so give it valid JSON.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  alias       = "unit-test"
  description = "unit test key"
  account_id  = "111111111111"
}

run "rotation_is_always_on" {
  command = plan

  assert {
    condition     = aws_kms_key.this.enable_key_rotation == true
    error_message = "Key rotation must be enabled."
  }

  assert {
    condition     = aws_kms_alias.this.name == "alias/unit-test"
    error_message = "Alias should be prefixed with alias/."
  }
}

run "rejects_short_deletion_window" {
  command = plan

  variables {
    deletion_window_in_days = 3
  }

  expect_failures = [var.deletion_window_in_days]
}

run "rejects_bad_account_id" {
  command = plan

  variables {
    account_id = "12345"
  }

  expect_failures = [var.account_id]
}

run "rejects_aws_reserved_alias" {
  command = plan

  variables {
    alias = "aws/s3"
  }

  expect_failures = [var.alias]
}
