# One-time setup, run by a human with admin credentials:
#   - S3 bucket for Terraform state (S3-native locking, no DynamoDB)
#   - GitHub OIDC provider and two CI roles:
#       plan  role: read-only, used on pull requests
#       apply role: deploys, only from GitHub environments dev/staging/prod
#
# The apply role can create IAM roles ONLY if they carry an approved
# permissions boundary, so a compromised pipeline can't mint an admin role.

terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = var.project
      Environment = "shared"
      Owner       = var.owner
      CostCenter  = var.cost_center
      ManagedBy   = "terraform"
      Repository  = var.github_repo
    }
  }
}

locals {
  github_host  = "token.actions.githubusercontent.com"
  oidc_arn     = "arn:aws:iam::${var.account_id}:oidc-provider/${local.github_host}"
  iam_prefix   = "arn:aws:iam::${var.account_id}"
  env_boundary = "${local.iam_prefix}:policy/${var.project}-*-boundary"
}

################################################################################
# State storage
################################################################################

module "state_key" {
  source = "../modules/kms-key"

  alias       = "${var.project}-tfstate"
  description = "Encrypts Terraform state"
  account_id  = var.account_id
}

module "state_bucket" {
  source = "../modules/secure-bucket"

  name        = "${var.project}-tfstate-${var.account_id}"
  kms_key_arn = module.state_key.key_arn

  # State history is the undo button; keep old versions for a year
  noncurrent_version_expiration_days = 365
}

################################################################################
# GitHub Actions OIDC
################################################################################

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 1 : 0

  url            = "https://${local.github_host}"
  client_id_list = ["sts.amazonaws.com"]
}

# Ceiling for both CI roles
data "aws_iam_policy_document" "ci_boundary" {
  #checkov:skip=CKV_AWS_109:A boundary is a ceiling, not a grant
  #checkov:skip=CKV_AWS_111:A boundary is a ceiling, not a grant
  #checkov:skip=CKV2_AWS_40:The apply role must create bounded IAM roles; its own policy limits which
  #checkov:skip=CKV_AWS_355:A boundary is a ceiling, not a grant
  #checkov:skip=CKV_AWS_290:A boundary is a ceiling, not a grant
  #checkov:skip=CKV_AWS_289:A boundary is a ceiling, not a grant
  statement {
    sid    = "AllowWhatTheStacksManage"
    effect = "Allow"
    actions = [
      "cloudwatch:*", "ec2:*", "iam:*", "kms:*", "logs:*", "s3:*",
      "sts:GetCallerIdentity", "tag:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyLongLivedCredentials"
    effect = "Deny"
    actions = [
      "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile",
      "iam:DeleteRolePermissionsBoundary", "organizations:*", "account:*",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "DenyOtherRegions"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    # Global services (IAM, STS) report us-east-1, so keep it in the list
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = distinct(concat(["us-east-1"], var.allowed_regions))
    }
  }
}

resource "aws_iam_policy" "ci_boundary" {
  name        = "${var.project}-ci-boundary"
  description = "Permissions boundary for the GitHub Actions roles"
  policy      = data.aws_iam_policy_document.ci_boundary.json
}

################################################################################
# Plan role (pull requests)
################################################################################

data "aws_iam_policy_document" "plan_state" {
  statement {
    sid       = "ReadState"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [module.state_bucket.bucket_arn, "${module.state_bucket.bucket_arn}/*"]
  }

  statement {
    sid       = "StateLockFile"
    actions   = ["s3:PutObject", "s3:DeleteObject"]
    resources = ["${module.state_bucket.bucket_arn}/*.tflock"]
  }

  statement {
    sid       = "DecryptState"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [module.state_key.key_arn]
  }
}

module "plan_role" {
  source = "../modules/iam-role"

  name                     = "${var.project}-github-plan"
  description              = "Read-only Terraform plan from GitHub Actions"
  permissions_boundary_arn = aws_iam_policy.ci_boundary.arn
  managed_policy_arns      = ["arn:aws:iam::aws:policy/ReadOnlyAccess"]
  inline_policies          = { state = data.aws_iam_policy_document.plan_state.json }

  oidc_trust = {
    provider_arn  = local.oidc_arn
    provider_host = local.github_host
    audience      = "sts.amazonaws.com"
    subjects = [
      "repo:${var.github_repo}:pull_request",
      "repo:${var.github_repo}:ref:refs/heads/main",
    ]
  }

  depends_on = [aws_iam_openid_connect_provider.github]
}

################################################################################
# Apply role (GitHub environments only, so prod waits for approval)
################################################################################

data "aws_iam_policy_document" "apply" {
  #checkov:skip=CKV_AWS_107:Deploy role; IAM actions are limited to the project prefix and boundary condition
  #checkov:skip=CKV_AWS_108:Deploy role must read and write S3 to manage buckets and state
  #checkov:skip=CKV_AWS_109:Role creation requires an approved permissions boundary (CreateBoundedRoles)
  #checkov:skip=CKV_AWS_111:Terraform deploy role manages these services; boundary and region deny cap it
  #checkov:skip=CKV_AWS_355:Terraform deploy role manages these services; boundary and region deny cap it
  #checkov:skip=CKV_AWS_356:Terraform deploy role manages these services; boundary and region deny cap it
  #checkov:skip=CKV_AWS_290:Terraform deploy role manages these services; boundary and region deny cap it
  statement {
    sid       = "ManageInfrastructure"
    actions   = ["cloudwatch:*", "ec2:*", "kms:*", "logs:*", "s3:*"]
    resources = ["*"]
  }

  # Roles under the project prefix, and only with an environment boundary
  statement {
    sid = "CreateBoundedRoles"
    actions = [
      "iam:AttachRolePolicy", "iam:CreateRole", "iam:DeleteRolePolicy",
      "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary", "iam:PutRolePolicy",
    ]
    resources = ["${local.iam_prefix}:role/${var.project}-*"]
    condition {
      test     = "ArnLike"
      variable = "iam:PermissionsBoundary"
      values   = [local.env_boundary]
    }
  }

  statement {
    sid = "ManageProjectRoles"
    actions = [
      "iam:DeleteRole", "iam:GetRole", "iam:GetRolePolicy", "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole", "iam:ListRolePolicies", "iam:PassRole",
      "iam:TagRole", "iam:UntagRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole",
      "iam:UpdateRoleDescription",
    ]
    resources = ["${local.iam_prefix}:role/${var.project}-*"]
  }

  statement {
    sid = "ManageProjectPolicies"
    actions = [
      "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicy",
      "iam:DeletePolicyVersion", "iam:GetPolicy", "iam:GetPolicyVersion",
      "iam:ListPolicyVersions", "iam:TagPolicy", "iam:UntagPolicy",
    ]
    resources = ["${local.iam_prefix}:policy/${var.project}-*"]
  }

  # ...but never the CI boundary itself
  statement {
    sid    = "ProtectCiBoundary"
    effect = "Deny"
    actions = [
      "iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion",
      "iam:SetDefaultPolicyVersion",
    ]
    resources = [aws_iam_policy.ci_boundary.arn]
  }

  statement {
    sid       = "UseStateKey"
    actions   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
    resources = [module.state_key.key_arn]
  }
}

module "apply_role" {
  source = "../modules/iam-role"

  name                     = "${var.project}-github-apply"
  description              = "Terraform apply from GitHub Actions environments"
  permissions_boundary_arn = aws_iam_policy.ci_boundary.arn
  inline_policies          = { deploy = data.aws_iam_policy_document.apply.json }

  oidc_trust = {
    provider_arn  = local.oidc_arn
    provider_host = local.github_host
    audience      = "sts.amazonaws.com"
    subjects      = [for env in ["dev", "staging", "prod"] : "repo:${var.github_repo}:environment:${env}"]
  }

  depends_on = [aws_iam_openid_connect_provider.github]
}
