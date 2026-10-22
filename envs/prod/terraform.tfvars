# Replace account_id with your own 12-digit AWS account ID before applying.
project     = "guardrails"
environment = "prod"
account_id  = "123456789012"

region          = "us-east-1"
allowed_regions = ["us-east-1", "us-west-2"] # us-west-2 reserved for DR
vpc_cidr        = "10.30.0.0/16"
azs             = ["us-east-1a", "us-east-1b", "us-east-1c"]

# NAT stays off to keep this demo cheap; a real prod workload would turn it on.
enable_nat_gateway       = false
kms_deletion_window_days = 30
public_https_ingress     = true

owner       = "platform-team"
cost_center = "cc-1001"
repository  = "JSR-codes/terraform-policy-guardrails"
