# The baseline every environment gets. envs/<env> only pass different inputs,
# so dev, staging and prod can't drift apart structurally.

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
  prefix = "${var.project}-${var.environment}"
}

################################################################################
# Permissions boundary: the ceiling for every IAM role in this environment
################################################################################

data "aws_iam_policy_document" "boundary" {
  #checkov:skip=CKV_AWS_109:A boundary is a ceiling, not a grant; it also denies all IAM actions
  #checkov:skip=CKV_AWS_111:A boundary is a ceiling, not a grant; resource scoping happens in each role's own policy
  #checkov:skip=CKV_AWS_355:A boundary is a ceiling, not a grant; resource scoping happens in each role's own policy
  #checkov:skip=CKV_AWS_290:A boundary is a ceiling, not a grant; resource scoping happens in each role's own policy
  #checkov:skip=CKV_AWS_289:A boundary is a ceiling, not a grant; resource scoping happens in each role's own policy
  statement {
    sid    = "AllowWorkloadServices"
    effect = "Allow"
    actions = [
      "cloudwatch:*",
      "dynamodb:*",
      "ec2:Describe*",
      "ecr:*",
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "logs:*",
      "s3:*",
      "secretsmanager:GetSecretValue",
      "sns:*",
      "sqs:*",
      "ssm:GetParameter*",
      "xray:*",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyIdentityEscalation"
    effect = "Deny"
    actions = [
      "iam:*",
      "organizations:*",
      "account:*",
      "sts:AssumeRoleWithSAML",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "DenyOtherRegions"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = var.allowed_regions
    }
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${local.prefix}-boundary"
  description = "Permissions boundary for every workload role in ${var.environment}"
  policy      = data.aws_iam_policy_document.boundary.json
}

################################################################################
# Encryption key, network, storage, access
################################################################################

module "kms" {
  source = "../../modules/kms-key"

  alias                   = local.prefix
  description             = "Encrypts ${var.environment} data and logs"
  account_id              = var.account_id
  service_principals      = ["logs.${var.region}.amazonaws.com"]
  deletion_window_in_days = var.kms_deletion_window_days
}

module "vpc" {
  source = "../../modules/vpc"

  name                     = local.prefix
  cidr_block               = var.vpc_cidr
  azs                      = var.azs
  enable_nat_gateway       = var.enable_nat_gateway
  permissions_boundary_arn = aws_iam_policy.boundary.arn
  flow_log_kms_key_arn     = module.kms.key_arn
  flow_log_retention_days  = var.flow_log_retention_days
}

module "data_bucket" {
  source = "../../modules/secure-bucket"

  name          = "${local.prefix}-data-${var.account_id}"
  kms_key_arn   = module.kms.key_arn
  force_destroy = var.environment == "dev"
}

module "app_sg" {
  source = "../../modules/security-group"

  name        = "${local.prefix}-app"
  description = "Application tier for ${var.environment}: HTTPS in, HTTPS out"
  vpc_id      = module.vpc.vpc_id
  ingress_rules = [{
    description = var.public_https_ingress ? "HTTPS from the internet" : "HTTPS from inside the VPC"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_ipv4   = var.public_https_ingress ? "0.0.0.0/0" : var.vpc_cidr
  }]
}

data "aws_iam_policy_document" "app" {
  statement {
    sid       = "ListDataBucket"
    actions   = ["s3:ListBucket"]
    resources = [module.data_bucket.bucket_arn]
  }

  statement {
    sid       = "ReadWriteObjects"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${module.data_bucket.bucket_arn}/*"]
  }

  statement {
    sid       = "UseDataKey"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey"]
    resources = [module.kms.key_arn]
  }
}

module "app_role" {
  source = "../../modules/iam-role"

  name                     = "${local.prefix}-app"
  description              = "Runtime role for the ${var.environment} application (ECS tasks)"
  trusted_services         = ["ecs-tasks.amazonaws.com"]
  permissions_boundary_arn = aws_iam_policy.boundary.arn
  inline_policies = {
    data-access = data.aws_iam_policy_document.app.json
  }
}
