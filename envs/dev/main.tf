module "baseline" {
  source = "../../stacks/baseline"

  project                  = var.project
  environment              = var.environment
  account_id               = var.account_id
  region                   = var.region
  allowed_regions          = var.allowed_regions
  vpc_cidr                 = var.vpc_cidr
  azs                      = var.azs
  enable_nat_gateway       = var.enable_nat_gateway
  kms_deletion_window_days = var.kms_deletion_window_days
  flow_log_retention_days  = var.flow_log_retention_days
  public_https_ingress     = var.public_https_ingress
}
