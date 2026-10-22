# secure-bucket

S3 bucket that is private, KMS-encrypted, versioned, TLS-1.2-only and ACL-free by default, with lifecycle housekeeping.

```hcl
module "data" {
  source = "../../modules/secure-bucket"

  name        = "acme-prod-data-123456789012"
  kms_key_arn = module.kms.key_arn
}
```

There is deliberately no option to make the bucket public or use S3-managed keys. `force_destroy` defaults to `false`.

Inputs and outputs are documented in `variables.tf` and `outputs.tf`. Tests: `terraform test` (mocked provider, no AWS needed).
