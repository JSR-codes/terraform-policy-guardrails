# Local equivalents of the CI jobs. TF=tofu works too.
TF ?= terraform
ENV ?= dev
ROOTS := modules/iam-role modules/kms-key modules/secure-bucket modules/security-group modules/vpc stacks/baseline envs/dev envs/staging envs/prod bootstrap
MODULES := $(filter modules/%,$(ROOTS))

export TF

.PHONY: check fmt validate test-modules test-policies policy policies regression checkov clean

check: fmt validate test-modules test-policies policies regression

fmt:
	$(TF) fmt -check -recursive -diff
	opa fmt --list --fail policies

validate:
	@for d in $(ROOTS); do \
		echo "== $$d"; \
		(cd $$d && $(TF) init -backend=false -input=false -no-color >/dev/null && $(TF) validate -no-color && tflint --config $(CURDIR)/.tflint.hcl --format compact) || exit 1; \
	done

test-modules:
	@for d in $(MODULES); do \
		echo "== $$d"; \
		(cd $$d && $(TF) init -input=false -no-color >/dev/null && $(TF) test -no-color) || exit 1; \
	done

test-policies:
	opa check --strict policies/terraform policies/tests
	opa test policies/terraform policies/tests --coverage --threshold 90 --format json | python3 -c "import json,sys; print('policy coverage: %.1f%%' % json.load(sys.stdin)['coverage'])"
	opa test policies/terraform policies/tests

# One environment: make policy ENV=prod
policy:
	scripts/policy-check.sh envs/$(ENV) $(ENV) --offline

policies:
	@for e in dev staging prod; do scripts/policy-check.sh envs/$$e $$e --offline || exit 1; done
	scripts/policy-check.sh bootstrap shared --offline

regression:
	scripts/regression-check.sh

checkov:
	checkov -d . --config-file .checkov.yaml --compact

clean:
	find . -name .terraform -type d -prune -exec rm -rf {} +
	rm -rf .policy-output
