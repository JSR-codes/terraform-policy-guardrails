# security-group

Security group whose rules are plain data, each with a mandatory description; egress defaults to HTTPS only.

```hcl
module "app_sg" {
  source = "../../modules/security-group"

  name        = "acme-prod-app"
  description = "App tier: HTTPS in from the load balancer"
  vpc_id      = module.vpc.vpc_id
  ingress_rules = [{
    description = "HTTPS from the VPC"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_ipv4   = "10.30.0.0/16"
  }]
}
```

Inbound all-protocol rules are rejected. Whether a port may face the internet is left to the NET-001 guardrail, which knows which environment it's checking.

Inputs and outputs are documented in `variables.tf` and `outputs.tf`. Tests: `terraform test` (mocked provider, no AWS needed).
