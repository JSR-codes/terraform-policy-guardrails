# Replace account_id with your own 12-digit AWS account ID before applying.
project     = "guardrails"
environment = "staging"
account_id  = "123456789012"

region          = "us-east-1"
allowed_regions = ["us-east-1"]
vpc_cidr        = "10.20.0.0/16"
azs             = ["us-east-1a", "us-east-1b"]

# Mirrors prod's shape at lower cost
enable_nat_gateway       = false
kms_deletion_window_days = 30
public_https_ingress     = false

owner       = "platform-team"
cost_center = "cc-1001"
repository  = "JSR-codes/terraform-policy-guardrails"
