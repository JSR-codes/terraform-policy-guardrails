terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_iam_policy_document" "trust" {
  dynamic "statement" {
    for_each = length(var.trusted_services) > 0 ? [1] : []
    content {
      sid     = "TrustedServices"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "Service"
        identifiers = var.trusted_services
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.trusted_role_arns) > 0 ? [1] : []
    content {
      sid     = "TrustedRoles"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.trusted_role_arns
      }
    }
  }

  # Web identity federation, e.g. GitHub Actions OIDC. Subjects are matched
  # with StringLike, so keep them as narrow as possible.
  dynamic "statement" {
    for_each = var.oidc_trust == null ? [] : [var.oidc_trust]
    content {
      sid     = "TrustedOidc"
      actions = ["sts:AssumeRoleWithWebIdentity"]
      principals {
        type        = "Federated"
        identifiers = [statement.value.provider_arn]
      }
      condition {
        test     = "StringEquals"
        variable = "${statement.value.provider_host}:aud"
        values   = [statement.value.audience]
      }
      condition {
        test     = "StringLike"
        variable = "${statement.value.provider_host}:sub"
        values   = statement.value.subjects
      }
    }
  }
}

resource "aws_iam_role" "this" {
  name                 = var.name
  description          = var.description
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  permissions_boundary = var.permissions_boundary_arn
  max_session_duration = var.max_session_duration
  tags                 = var.tags

  lifecycle {
    precondition {
      condition     = length(var.trusted_services) + length(var.trusted_role_arns) > 0 || var.oidc_trust != null
      error_message = "Set trusted_services, trusted_role_arns or oidc_trust: a role nobody can assume is a mistake."
    }
  }
}

resource "aws_iam_role_policy_attachment" "managed" {
  for_each   = toset(var.managed_policy_arns)
  role       = aws_iam_role.this.name
  policy_arn = each.value
}

resource "aws_iam_role_policy" "inline" {
  for_each = var.inline_policies
  name     = each.key
  role     = aws_iam_role.this.id
  policy   = each.value
}
