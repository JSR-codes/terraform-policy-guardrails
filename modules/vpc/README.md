# vpc

VPC with private and public subnets in each AZ, a locked-down default security group, optional single NAT gateway, and KMS-encrypted VPC flow logs to CloudWatch.

```hcl
module "vpc" {
  source = "../../modules/vpc"

  name                     = "acme-prod"
  cidr_block               = "10.30.0.0/16"
  azs                      = ["us-east-1a", "us-east-1b", "us-east-1c"]
  permissions_boundary_arn = aws_iam_policy.boundary.arn
  flow_log_kms_key_arn     = module.kms.key_arn
}
```

Private subnets are `/20`s from the bottom of the range, public subnets `/24`s from `.240` up. AZ names are explicit, so adding a zone never reshuffles existing subnets.

Inputs and outputs are documented in `variables.tf` and `outputs.tf`. Tests: `terraform test` (mocked provider, no AWS needed).
