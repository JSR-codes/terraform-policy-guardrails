# iam-role

IAM role that always carries a permissions boundary, trusting AWS services, specific roles or a GitHub OIDC subject.

```hcl
module "app_role" {
  source = "../../modules/iam-role"

  name                     = "acme-prod-app"
  description              = "Runtime role for the prod app"
  trusted_services         = ["ecs-tasks.amazonaws.com"]
  permissions_boundary_arn = aws_iam_policy.boundary.arn
  inline_policies          = { data = data.aws_iam_policy_document.app.json }
}
```

`permissions_boundary_arn` has no default, so a role without one can't be created. Wildcard trusted ARNs and bare `*` / `repo:*` OIDC subjects are rejected at plan time.

Inputs and outputs are documented in `variables.tf` and `outputs.tf`. Tests: `terraform test` (mocked provider, no AWS needed).
