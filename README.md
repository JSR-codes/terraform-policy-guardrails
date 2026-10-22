# terraform-policy-guardrails

[![ci](https://github.com/JSR-codes/terraform-policy-guardrails/actions/workflows/ci.yml/badge.svg)](https://github.com/JSR-codes/terraform-policy-guardrails/actions/workflows/ci.yml)

I built this to practice something most platform teams end up needing: a way to stop bad infrastructure changes *before* they get applied, instead of finding them later in a security review.

The repo has a small set of Terraform modules for AWS, three environments (dev, staging, prod) built from those modules, and a set of OPA/Rego policies that check every Terraform plan. If a change opens SSH to the internet, creates an unencrypted bucket, or gives a role `*:*`, the pull request fails and tells you exactly which resource broke which rule.

## The basic idea

Checkov and similar scanners read the `.tf` files. That's useful, but the code doesn't tell you everything. Variables, module inputs and provider defaults are only resolved at plan time. So I run the policies against the plan instead:

```
terraform plan -out tfplan
terraform show -json tfplan > plan.json
conftest test plan.json   # with the settings for that environment
```

Because the policies see the real plan, the same rule can behave differently per environment. Prod needs 3 AZs, only allows port 443 from the internet, and blocks deleting buckets or KMS keys. Dev is more relaxed.

The part I like most: **pull requests don't need AWS credentials**. None of the modules use data sources that call AWS, so CI copies in `ci/ci_override.tf` (local state, fake credentials) and gets a complete plan with no account at all. The deploy pipeline then plans again against real state and runs the same checks before applying.

Rough flow:

```
PR opened
  ├── fmt / validate / tflint
  ├── terraform test on each module
  ├── opa test on the policies
  ├── checkov
  ├── offline plan of dev, staging, prod, bootstrap → conftest
  └── plan of examples/noncompliant → must FAIL (proves the rules still work)

merged to main
  └── dev → staging → (manual approval) → prod
        each step: OIDC role → real plan → conftest → apply that same plan
```

## What's in here

```
modules/           vpc, secure-bucket, kms-key, iam-role, security-group (each has tests/)
stacks/baseline/   what every environment gets, built from the modules
envs/              dev, staging, prod: same code, different terraform.tfvars
bootstrap/         state bucket + GitHub OIDC roles, run once by hand
policies/          Rego rules, unit tests, per-env settings, waivers
examples/noncompliant/   intentionally insecure, used as a regression test
scripts/           policy-check.sh and regression-check.sh
```

A few choices in the modules that are deliberate:

- `secure-bucket` has no option to turn off encryption or make the bucket public. If you need that, you shouldn't be using this module.
- `iam-role` requires a permissions boundary. There's no default, so you can't forget it.
- `kms-key` always has rotation on.
- `vpc` ships flow logs (KMS-encrypted) and strips all rules from the default security group.

## The rules

| Rule | Checks | Differs by env? |
|---|---|---|
| TAG-001 | Project, Environment, Owner and CostCenter tags are set | |
| TAG-002 | The Environment tag matches where it's being deployed | |
| S3-001 | Public access block, all four settings on | |
| S3-002 | Default encryption with KMS | |
| S3-003 | Versioning on | |
| S3-004 | No public canned ACLs | |
| NET-001 | Only web ports open to 0.0.0.0/0 | dev/staging: 80, 443. prod: 443 only |
| NET-002 | Every VPC has flow logs | |
| NET-003 | Subnets spread across enough AZs | prod needs 3, others 2 |
| IAM-001 | No `Allow *` on `*` | |
| IAM-002 | Every role has a permissions boundary | |
| IAM-003 | No trust policy that trusts `*` | |
| IAM-004 | No IAM users or access keys | |
| IAM-005 | GitHub OIDC trust is pinned to a repo (no `repo:my-org/*`) | |
| KMS-001 | Key rotation on | |
| KMS-002 | Minimum deletion window | 7 days in dev, 30 elsewhere |
| EC2-001 | Instance type is on the allow-list | small types in dev, bigger in prod |
| EC2-002 | IMDSv2 required | |
| REG-001 | Only approved regions | prod also allows us-west-2 |
| CHG-001 | Deleting/replacing a bucket, key or database | warning in dev, blocked in staging/prod |
| COST-001 | NAT gateway in dev (it's ~$32/month) | warning only |
| EXC-001..003 | Waivers have a reason, an approver and a short expiry | |

The env-specific values are in `policies/data/env/*.yaml`, so tightening prod is a one-line change.

Here's some of what you get when the insecure example is checked against prod:

```
[NET-001] aws_security_group.ssh: tcp ports 22-22 open to 0.0.0.0/0; only [443] may face the internet
[IAM-005] aws_iam_role.github: GitHub OIDC trust uses wildcard subject "repo:my-org/*"
[KMS-002] aws_kms_key.weak: deletion window is 7 days; prod requires at least 30
[NET-003] plan: subnets span 1 AZ(s) ["eu-west-1a"]; prod needs at least 3
```

In GitHub Actions the same output shows up as a table on the run summary page.

## Running it locally

You need Terraform 1.11+ (OpenTofu works too, use `TF=tofu`), conftest, opa and tflint. No AWS account needed.

```bash
make check             # same checks as CI
make policy ENV=prod   # just one environment
make regression        # confirm the insecure example still gets caught
```

## Deploying to AWS

This creates real resources. With the NAT gateway off (the default), the cost is mostly the KMS keys at about $1/month each, plus a few cents for logs and storage. Destroy it when you're done.

First, the bootstrap. Put your account ID in `bootstrap/terraform.tfvars`, then:

```bash
cd bootstrap
terraform init
terraform apply
terraform output
```

That gives you the state bucket name and two IAM roles for GitHub Actions: a read-only one for plans and one for deploys. The deploy role can create IAM roles, but **only** if they carry one of the environment permissions boundaries. That way a compromised pipeline can't just make itself an admin role.

Then for each environment, copy `backend.hcl.example` to `backend.hcl`, set `account_id` in `terraform.tfvars`, and either apply by hand:

```bash
cd envs/dev
terraform init -backend-config=backend.hcl
terraform apply
```

...or let GitHub Actions do it:

1. Create environments `dev`, `staging` and `prod` in the repo settings. Add yourself as a required reviewer on `prod`.
2. Add the secret `AWS_APPLY_ROLE_ARN` (from `terraform output apply_role_arn`).
3. Add the variables `TF_STATE_BUCKET` (from `terraform output state_bucket`) and `DEPLOY_ENABLED=true`.
4. Push to main.

## When a rule needs an exception

Sometimes you really do need to delete a prod bucket, for example during a migration. Instead of turning the rule off, add a waiver to `policies/data/exceptions.yaml`:

```yaml
exceptions:
  - rule: CHG-001
    address: module.baseline.module.data_bucket.*
    reason: Moving data to the new bucket, ticket CHG-1234
    approved_by: platform-lead
    expires: "2026-12-01T00:00:00Z"
```

It only covers that one rule on those resources. It goes through PR review like anything else, and it stops working on its own after it expires. The policies also refuse waivers that are missing a reason or approver, or that last more than 90 days.

## Adding a new rule

1. Write it in `policies/terraform/` with a new ID.
2. Add tests for the passing and failing cases in `policies/tests/`.
3. Add something that breaks it to `examples/noncompliant/main.tf`, and the ID to `expected-violations.txt`.

Step 3 is the one that matters long term. If someone later "simplifies" the rule and it stops catching that case, the regression check in CI fails.

## Things I ran into

**Untagged resources were passing the tag check.** If a resource has no tags at all *and* the provider has no default tags, Terraform reports `tags_all` as unknown at plan time, and my first version skipped unknown values. The insecure example caught this: the VPC got flagged but the bucket, key and instance didn't. Now the rule falls back to the resource's own `tags`.

**Waivers with `module.data.*` matched nothing.** OPA's `glob.match` treats `.` as a separator by default, so `*` stopped at the first dot. Passing `null` as the delimiter fixed it. I also added a test so `module.data.*` doesn't accidentally match `module.database`.

**Mocked providers return random strings.** `terraform test` with `mock_provider` generates random values for computed attributes, so things like `aws_iam_policy_document.json` came back as garbage and failed validation. The tests set valid placeholder values for those.

**S3 state locking.** I started with the usual S3 + DynamoDB setup, then switched to `use_lockfile = true`. Terraform 1.11+ can lock in S3 directly, and the DynamoDB option is deprecated.

## Limitations

- Some values aren't known until apply, like an inline policy that references a bucket ARN created in the same run. The policies skip those, and the permissions boundary covers them at runtime.
- The plan doesn't have resource IDs yet, so "does this bucket have a public access block" is matched by module. That works with how the modules are written, but it would get confused by two buckets declared side by side in one root module.
- Everything lives in one AWS account with prefixed names. In a real setup each environment would be its own account, with SCPs on top.

## Results

Haven't measured these on a real deployment yet. I'll fill them in once I do.

| | |
|---|---|
| PR check time | |
| Deploy time, dev to staging | |
| Monthly cost, all three envs | |

## License

MIT
