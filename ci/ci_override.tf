# Copied into an environment as ci_override.tf by CI (and scripts/offline-plan.sh)
# so `plan` runs with no AWS account: local state, fake credentials, no API calls.
# This works because the modules use no data sources that call AWS.
terraform {
  backend "local" {}
}

provider "aws" {
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}
