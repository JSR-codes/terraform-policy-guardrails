package terraform.s3_test

import data.fixtures
import data.terraform.s3
import rego.v1

m := "module.bucket"

compliant_bucket := [
	fixtures.create_in(m, "aws_s3_bucket.this", "aws_s3_bucket", {"bucket": "b"}),
	fixtures.create_in(m, "aws_s3_bucket_public_access_block.this", "aws_s3_bucket_public_access_block", {
		"block_public_acls": true, "block_public_policy": true,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	}),
	fixtures.create_in(m, "aws_s3_bucket_server_side_encryption_configuration.this", "aws_s3_bucket_server_side_encryption_configuration", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]}),
	fixtures.create_in(m, "aws_s3_bucket_versioning.this", "aws_s3_bucket_versioning", {"versioning_configuration": [{"status": "Enabled"}]}),
]

test_compliant_bucket_passes if {
	count(s3.deny) == 0 with input as fixtures.plan(compliant_bucket) with data.guardrails as fixtures.prod
}

test_bare_bucket_fails_three_rules if {
	denials := s3.deny with input as fixtures.plan([compliant_bucket[0]]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "S3-001")
	fixtures.fired(denials, "S3-002")
	fixtures.fired(denials, "S3-003")
}

test_partial_public_access_block_fails if {
	weak := fixtures.create_in(m, "aws_s3_bucket_public_access_block.this", "aws_s3_bucket_public_access_block", {
		"block_public_acls": true, "block_public_policy": false,
		"ignore_public_acls": true, "restrict_public_buckets": true,
	})
	resources := [compliant_bucket[0], weak, compliant_bucket[2], compliant_bucket[3]]
	denials := s3.deny with input as fixtures.plan(resources) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "S3-001")
}

test_aes256_rejected_when_kms_required if {
	aes := fixtures.create_in(m, "aws_s3_bucket_server_side_encryption_configuration.this", "aws_s3_bucket_server_side_encryption_configuration", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]})
	resources := [compliant_bucket[0], compliant_bucket[1], aes, compliant_bucket[3]]
	denials := s3.deny with input as fixtures.plan(resources) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "S3-002")
}

test_aes256_allowed_when_kms_not_required if {
	aes := fixtures.create_in(m, "aws_s3_bucket_server_side_encryption_configuration.this", "aws_s3_bucket_server_side_encryption_configuration", {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]})
	resources := [compliant_bucket[0], compliant_bucket[1], aes, compliant_bucket[3]]
	settings := object.union(fixtures.prod, {"require_kms_for_s3": false})
	count(s3.deny) == 0 with input as fixtures.plan(resources) with data.guardrails as settings
}

test_public_acl_fails if {
	acl := fixtures.create("aws_s3_bucket_acl.x", "aws_s3_bucket_acl", {"acl": "public-read"})
	denials := s3.deny with input as fixtures.plan(array.concat(compliant_bucket, [acl])) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "S3-004")
}

# A bucket in a different module must not borrow another bucket's controls
test_controls_do_not_leak_across_modules if {
	other := fixtures.create_in("module.other", "aws_s3_bucket.this", "aws_s3_bucket", {"bucket": "other"})
	denials := s3.deny with input as fixtures.plan(array.concat(compliant_bucket, [other])) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "S3-001")
	some msg in denials
	contains(msg, "module.other")
}
