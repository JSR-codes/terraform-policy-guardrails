package terraform.misc_test

import data.fixtures
import data.terraform.compute
import data.terraform.kms
import data.terraform.region
import rego.v1

# --- KMS ---------------------------------------------------------------------

test_rotation_off_denied if {
	k := fixtures.create("aws_kms_key.k", "aws_kms_key", {"enable_key_rotation": false, "deletion_window_in_days": 30})
	denials := kms.deny with input as fixtures.plan([k]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "KMS-001")
}

test_asymmetric_key_exempt_from_rotation if {
	k := fixtures.create("aws_kms_key.k", "aws_kms_key", {"enable_key_rotation": false, "customer_master_key_spec": "RSA_2048", "deletion_window_in_days": 30})
	count(kms.deny) == 0 with input as fixtures.plan([k]) with data.guardrails as fixtures.prod
}

test_short_window_ok_in_dev_not_prod if {
	k := [fixtures.create("aws_kms_key.k", "aws_kms_key", {"enable_key_rotation": true, "deletion_window_in_days": 7})]
	count(kms.deny) == 0 with input as fixtures.plan(k) with data.guardrails as fixtures.dev
	denials := kms.deny with input as fixtures.plan(k) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "KMS-002")
}

test_unset_window_means_30_days if {
	k := fixtures.create("aws_kms_key.k", "aws_kms_key", {"enable_key_rotation": true, "deletion_window_in_days": null})
	count(kms.deny) == 0 with input as fixtures.plan([k]) with data.guardrails as fixtures.prod
}

# --- Compute -------------------------------------------------------------------

instance(itype, tokens) := fixtures.create("aws_instance.i", "aws_instance", {"instance_type": itype, "metadata_options": [{"http_tokens": tokens}]})

test_allowed_instance_passes if {
	count(compute.deny) == 0 with input as fixtures.plan([instance("m7i.large", "required")]) with data.guardrails as fixtures.prod
}

test_instance_type_per_environment if {
	i := [instance("m7i.large", "required")]
	denials := compute.deny with input as fixtures.plan(i) with data.guardrails as fixtures.dev
	fixtures.fired(denials, "EC2-001")
}

test_imdsv1_denied if {
	denials := compute.deny with input as fixtures.plan([instance("m7i.large", "optional")]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "EC2-002")
}

test_launch_template_checked_too if {
	lt := fixtures.create("aws_launch_template.lt", "aws_launch_template", {"instance_type": "x2iedn.32xlarge", "metadata_options": []})
	denials := compute.deny with input as fixtures.plan([lt]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "EC2-001")
	fixtures.fired(denials, "EC2-002")
}

# --- Regions -------------------------------------------------------------------

provider_plan(expr, vars) := {
	"resource_changes": [],
	"configuration": {"provider_config": {"aws": {"name": "aws", "expressions": {"region": expr}}}},
	"variables": vars,
}

test_literal_region_checked if {
	p := provider_plan({"constant_value": "ap-south-1"}, {})
	denials := region.deny with input as p with data.guardrails as fixtures.prod
	fixtures.fired(denials, "REG-001")
}

test_region_from_variable_checked if {
	p := provider_plan({"references": ["var.region"]}, {"region": {"value": "ap-south-1"}})
	denials := region.deny with input as p with data.guardrails as fixtures.prod
	fixtures.fired(denials, "REG-001")
}

test_approved_region_passes if {
	p := provider_plan({"references": ["var.region"]}, {"region": {"value": "us-east-1"}})
	count(region.deny) == 0 with input as p with data.guardrails as fixtures.prod
}

test_per_resource_region_override_checked if {
	r := fixtures.create("aws_s3_bucket.b", "aws_s3_bucket", {"region": "eu-west-1"})
	denials := region.deny with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "REG-001")
}
