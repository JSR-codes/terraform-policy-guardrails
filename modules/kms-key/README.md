# kms-key

Customer-managed KMS key with rotation always on, a scoped key policy (admins, users, AWS services limited to this account) and an alias.

```hcl
module "kms" {
  source = "../../modules/kms-key"

  alias              = "acme-prod"
  description        = "Encrypts prod data and logs"
  account_id         = "123456789012"
  service_principals = ["logs.us-east-1.amazonaws.com"]
}
```

Rotation can't be turned off. The deletion window is validated to AWS's 7-30 day range; the guardrails then require 30 in staging and prod.

Inputs and outputs are documented in `variables.tf` and `outputs.tf`. Tests: `terraform test` (mocked provider, no AWS needed).
