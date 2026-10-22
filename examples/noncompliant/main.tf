# DELIBERATELY INSECURE. Never apply this.
#
# Each block breaks one or more guardrails. CI plans it offline and fails if
# any rule in expected-violations.txt does NOT fire, which proves the
# policies still catch what they claim to.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# REG-001: unapproved region. TAG-001: no default_tags.
provider "aws" {
  region = "eu-west-1"
}

# S3-001, S3-002, S3-003: no public access block, encryption or versioning
resource "aws_s3_bucket" "open" {
  bucket = "guardrails-demo-open-bucket"
}

# S3-004: public canned ACL
resource "aws_s3_bucket_acl" "open" {
  bucket = aws_s3_bucket.open.id
  acl    = "public-read"
}

# NET-002: VPC without flow logs. TAG-002: Environment tag from another env.
resource "aws_vpc" "main" {
  cidr_block = "10.99.0.0/16"
  tags = {
    Environment = "dev"
  }
}

# NET-003: one AZ only
resource "aws_subnet" "only" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.99.1.0/24"
  availability_zone = "eu-west-1a"
}

# NET-001: SSH open to the internet
resource "aws_security_group" "ssh" {
  name        = "ssh-from-anywhere"
  description = "Do not do this"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# IAM-001: full admin policy
resource "aws_iam_policy" "admin" {
  name = "everything"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

# IAM-002: no boundary. IAM-003: anyone can assume it.
resource "aws_iam_role" "anyone" {
  name = "assumable-by-anyone"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = "*" } }]
  })
}

# IAM-005: any repository in the GitHub account can assume this role
resource "aws_iam_role" "github" {
  name                 = "github-any-repo"
  permissions_boundary = "arn:aws:iam::123456789012:policy/boundary"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com" }
      Condition = { StringLike = { "token.actions.githubusercontent.com:sub" = "repo:my-org/*" } }
    }]
  })
}

# IAM-004: long-lived user credentials
resource "aws_iam_user" "ci" {
  name = "ci-bot"
}

resource "aws_iam_access_key" "ci" {
  user = aws_iam_user.ci.name
}

# KMS-001: no rotation. KMS-002: 7-day window in prod.
resource "aws_kms_key" "weak" {
  description             = "no rotation"
  enable_key_rotation     = false
  deletion_window_in_days = 7
}

# EC2-001: oversized for the environment. EC2-002: IMDSv1 allowed.
resource "aws_instance" "big" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.2xlarge"
  subnet_id     = aws_subnet.only.id
}
