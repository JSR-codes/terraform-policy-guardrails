terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_iam_policy_document" "this" {
  #checkov:skip=CKV_AWS_111:In a key policy, Resource "*" means this key only
  #checkov:skip=CKV_AWS_356:In a key policy, Resource "*" means this key only
  #checkov:skip=CKV_AWS_109:Standard root delegation so IAM policies can grant access

  # Delegates access control to IAM in this account (AWS default key policy).
  statement {
    sid       = "AccountRoot"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.account_id}:root"]
    }
  }

  dynamic "statement" {
    for_each = length(var.admin_role_arns) > 0 ? [1] : []
    content {
      sid = "KeyAdministrators"
      actions = [
        "kms:CancelKeyDeletion", "kms:Create*", "kms:Delete*", "kms:Describe*",
        "kms:Disable*", "kms:Enable*", "kms:Get*", "kms:List*", "kms:Put*",
        "kms:Revoke*", "kms:ScheduleKeyDeletion", "kms:TagResource",
        "kms:UntagResource", "kms:Update*",
      ]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.admin_role_arns
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.user_role_arns) > 0 ? [1] : []
    content {
      sid       = "KeyUsers"
      actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
      resources = ["*"]
      principals {
        type        = "AWS"
        identifiers = var.user_role_arns
      }
    }
  }

  # AWS services (e.g. CloudWatch Logs) that encrypt on your behalf,
  # limited to requests coming from this account.
  dynamic "statement" {
    for_each = length(var.service_principals) > 0 ? [1] : []
    content {
      sid       = "AwsServices"
      actions   = ["kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
      resources = ["*"]
      principals {
        type        = "Service"
        identifiers = var.service_principals
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [var.account_id]
      }
    }
  }
}

resource "aws_kms_key" "this" {
  description             = var.description
  enable_key_rotation     = true
  rotation_period_in_days = var.rotation_period_in_days
  deletion_window_in_days = var.deletion_window_in_days
  policy                  = data.aws_iam_policy_document.this.json
  tags                    = var.tags
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.alias}"
  target_key_id = aws_kms_key.this.key_id
}
