# Generated policy JSON is random in a mock provider, so give it valid JSON.
mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }
}

variables {
  name        = "unit-test-bucket"
  kms_key_arn = "arn:aws:kms:us-east-1:111111111111:key/00000000-0000-0000-0000-000000000000"
}

run "locked_down_by_default" {
  command = plan

  assert {
    condition = (
      aws_s3_bucket_public_access_block.this.block_public_acls &&
      aws_s3_bucket_public_access_block.this.block_public_policy &&
      aws_s3_bucket_public_access_block.this.ignore_public_acls &&
      aws_s3_bucket_public_access_block.this.restrict_public_buckets
    )
    error_message = "All four public access block settings must be on."
  }

  assert {
    condition     = one(aws_s3_bucket_ownership_controls.this.rule).object_ownership == "BucketOwnerEnforced"
    error_message = "ACLs must be disabled."
  }

  assert {
    condition     = aws_s3_bucket.this.force_destroy == false
    error_message = "force_destroy must default to false."
  }
}

run "kms_encryption" {
  command = plan

  assert {
    condition = alltrue([
      for r in aws_s3_bucket_server_side_encryption_configuration.this.rule :
      alltrue([for d in r.apply_server_side_encryption_by_default : d.sse_algorithm == "aws:kms" && d.kms_master_key_id == var.kms_key_arn])
    ])
    error_message = "Default encryption must use the supplied KMS key."
  }
}

run "versioning_toggle" {
  command = plan

  variables {
    versioning_enabled = false
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.this.versioning_configuration).status == "Suspended"
    error_message = "versioning_enabled = false should suspend versioning."
  }
}

run "rejects_uppercase_name" {
  command = plan

  variables {
    name = "Bad_Bucket"
  }

  expect_failures = [var.name]
}

run "rejects_missing_kms_arn" {
  command = plan

  variables {
    kms_key_arn = "AES256"
  }

  expect_failures = [var.kms_key_arn]
}
