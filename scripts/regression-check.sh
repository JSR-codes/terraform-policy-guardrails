#!/usr/bin/env bash
# Proves the guardrails still bite: checks examples/noncompliant against prod
# settings and fails unless every rule in expected-violations.txt fires.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
EXPECTED="$REPO/examples/noncompliant/expected-violations.txt"

output="$("$REPO/scripts/policy-check.sh" examples/noncompliant prod --offline 2>&1)"
status=$?

if [ $status -eq 0 ]; then
  echo "FAIL: the noncompliant example passed policy checks. Guardrails are not working."
  exit 1
fi

missing=()
while read -r rule; do
  [[ -z "$rule" || "$rule" == \#* ]] && continue
  if grep -q "\[$rule\]" <<<"$output"; then
    echo "  caught  $rule"
  else
    echo "  MISSED  $rule"
    missing+=("$rule")
  fi
done <"$EXPECTED"

if [ ${#missing[@]} -gt 0 ]; then
  echo
  echo "FAIL: ${#missing[@]} rule(s) did not fire: ${missing[*]}"
  echo "--- conftest output ---"
  echo "$output"
  exit 1
fi

echo
echo "OK: every expected rule fired ($(grep -c '^FAIL' <<<"$output") violations in total)."
