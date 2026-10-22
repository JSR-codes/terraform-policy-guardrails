#!/usr/bin/env bash
# Plan a Terraform root and check the plan against the guardrails.
#
#   scripts/policy-check.sh <root-dir> <env> [--offline]
#
#   <root-dir>  e.g. envs/prod or examples/noncompliant
#   <env>       which policies/data/env/<env>.yaml settings to apply
#   --offline   plan with no AWS account (local state, fake credentials).
#               Used on pull requests; the real pipeline plans with AWS.
#
# Environment variables:
#   TF=tofu               use OpenTofu instead of Terraform
#   TF_STATE_BUCKET       (online) state bucket; otherwise backend.hcl is used
#   TF_STATE_REGION       (online) state bucket region, default us-east-1
#   PLAN_OUT=path         keep the binary plan so the exact same plan is applied
set -euo pipefail

ROOT_DIR="${1:?usage: policy-check.sh <root-dir> <env> [--offline]}"
ENV_NAME="${2:?usage: policy-check.sh <root-dir> <env> [--offline]}"
MODE="${3:-}"
TF="${TF:-terraform}"

REPO="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; rm -f "$REPO/$ROOT_DIR/ci_override.tf"' EXIT

cd "$REPO/$ROOT_DIR"

if [ "$MODE" = "--offline" ]; then
  cp "$REPO/ci/ci_override.tf" ./ci_override.tf
  rm -rf .terraform/terraform.tfstate terraform.tfstate
  "$TF" init -input=false -no-color -reconfigure >/dev/null
elif [ -n "${TF_STATE_BUCKET:-}" ]; then
  "$TF" init -input=false -no-color \
    -backend-config="bucket=${TF_STATE_BUCKET}" \
    -backend-config="region=${TF_STATE_REGION:-us-east-1}" >/dev/null
else
  "$TF" init -input=false -no-color -backend-config=backend.hcl >/dev/null
fi

"$TF" plan -input=false -no-color -lock=false -out="$WORK/tfplan" >"$WORK/plan.txt"
"$TF" show -json "$WORK/tfplan" >"$WORK/plan.json"
grep -E '^(Plan:|No changes)' "$WORK/plan.txt" || true

[ -n "${PLAN_OUT:-}" ] && cp "$WORK/tfplan" "$PLAN_OUT"

# Keep a copy for CI artifacts
mkdir -p "$REPO/.policy-output"
cp "$WORK/plan.json" "$REPO/.policy-output/${ENV_NAME}-$(basename "$ROOT_DIR").plan.json"

set +e
conftest test "$WORK/plan.json" \
  --policy "$REPO/policies/terraform" \
  --data "$REPO/policies/data/env/${ENV_NAME}.yaml" \
  --data "$REPO/policies/data/exceptions.yaml" \
  --all-namespaces \
  --no-color | tee "$WORK/conftest.txt"
result=${PIPESTATUS[0]}
set -e

# Readable summary on the GitHub Actions run page
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    if [ "$result" -eq 0 ]; then
      echo "### ✅ \`$ROOT_DIR\` passes the **$ENV_NAME** guardrails"
    else
      echo "### ❌ \`$ROOT_DIR\` violates the **$ENV_NAME** guardrails"
    fi
    echo
    grep -E '^(Plan:|No changes)' "$WORK/plan.txt" || true
    echo
    if grep -qE '^(FAIL|WARN)' "$WORK/conftest.txt"; then
      echo '| Result | Rule | Resource and reason |'
      echo '|---|---|---|'
      grep -E '^(FAIL|WARN)' "$WORK/conftest.txt" |
        sed -E 's/^(FAIL|WARN) - [^ ]+ - [^ ]+ - \[([A-Z0-9-]+)\] (.*)$/| \1 | \2 | \3 |/'
    fi
    echo
  } >>"$GITHUB_STEP_SUMMARY"
fi

exit "$result"
