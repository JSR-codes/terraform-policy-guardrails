package terraform.changes_test

import data.fixtures
import data.terraform.changes
import data.terraform.exceptions
import data.terraform.s3
import rego.v1

bucket := "module.data.aws_s3_bucket.this"

# --- CHG-001 -------------------------------------------------------------------

test_deleting_bucket_blocked_in_prod if {
	denials := changes.deny with input as fixtures.plan([fixtures.delete(bucket, "aws_s3_bucket")]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "CHG-001")
}

test_replacing_key_blocked_in_prod if {
	denials := changes.deny with input as fixtures.plan([fixtures.replace("aws_kms_key.k", "aws_kms_key")]) with data.guardrails as fixtures.prod
	some msg in denials
	contains(msg, "replace")
}

test_deleting_bucket_only_warns_in_dev if {
	p := fixtures.plan([fixtures.delete(bucket, "aws_s3_bucket")])
	count(changes.deny) == 0 with input as p with data.guardrails as fixtures.dev
	count(changes.warn) == 1 with input as p with data.guardrails as fixtures.dev
}

test_deleting_stateless_resource_is_fine if {
	count(changes.deny) == 0 with input as fixtures.plan([fixtures.delete("aws_route.r", "aws_route")]) with data.guardrails as fixtures.prod
}

test_nat_gateway_warns_in_dev if {
	nat := fixtures.create("aws_nat_gateway.n", "aws_nat_gateway", {})
	count(changes.warn) == 1 with input as fixtures.plan([nat]) with data.guardrails as fixtures.dev
}

# --- Exceptions ------------------------------------------------------------------

waiver(expires) := [{
	"rule": "CHG-001",
	"address": "module.data.*",
	"reason": "planned migration",
	"approved_by": "lead",
	"expires": expires,
}]

test_active_exception_waives_violation if {
	p := fixtures.plan([fixtures.delete(bucket, "aws_s3_bucket")])
	count(changes.deny) == 0 with input as p with data.guardrails as fixtures.prod with data.exceptions as waiver("2099-12-31T00:00:00Z")
}

test_expired_exception_no_longer_applies if {
	p := fixtures.plan([fixtures.delete(bucket, "aws_s3_bucket")])
	denials := changes.deny with input as p with data.guardrails as fixtures.prod with data.exceptions as waiver("2020-01-01T00:00:00Z")
	fixtures.fired(denials, "CHG-001")
}

test_exception_only_covers_its_own_rule if {
	# A CHG-001 waiver must not silence S3 rules on the same resource
	p := fixtures.plan([fixtures.create_in("module.data", "aws_s3_bucket.this", "aws_s3_bucket", {"bucket": "b"})])
	denials := s3.deny with input as p with data.guardrails as fixtures.prod with data.exceptions as waiver("2099-12-31T00:00:00Z")
	fixtures.fired(denials, "S3-001")
}

test_exception_glob_does_not_match_similar_module_names if {
	p := fixtures.plan([fixtures.delete("module.database.aws_s3_bucket.this", "aws_s3_bucket")])
	denials := changes.deny with input as p with data.guardrails as fixtures.prod with data.exceptions as waiver("2099-12-31T00:00:00Z")
	fixtures.fired(denials, "CHG-001")
}

# --- Exception hygiene ---------------------------------------------------------

test_complete_short_exception_is_valid if {
	soon := time.format([time.now_ns() + ((((30 * 24) * 60) * 60) * 1000000000), "UTC", "2006-01-02T15:04:05Z07:00"])
	count(exceptions.deny) == 0 with input as {} with data.exceptions as waiver(soon)
}

test_exception_without_reason_denied if {
	e := [object.remove(waiver("2099-12-31T00:00:00Z")[0], ["reason"])]
	denials := exceptions.deny with input as {} with data.exceptions as e
	fixtures.fired(denials, "EXC-001")
}

test_open_ended_exception_denied if {
	denials := exceptions.deny with input as {} with data.exceptions as waiver("2099-12-31T00:00:00Z")
	fixtures.fired(denials, "EXC-002")
}

test_expired_exception_warns if {
	count(exceptions.warn) == 1 with input as {} with data.exceptions as waiver("2020-01-01T00:00:00Z")
}
