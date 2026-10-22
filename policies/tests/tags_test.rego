package terraform.tags_test

import data.fixtures
import data.terraform.tags
import rego.v1

test_fully_tagged_passes if {
	r := fixtures.create("aws_vpc.v", "aws_vpc", {"tags_all": fixtures.good_tags})
	count(tags.deny) == 0 with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
}

test_missing_tag_denied if {
	r := fixtures.create("aws_vpc.v", "aws_vpc", {"tags_all": object.remove(fixtures.good_tags, ["Owner"])})
	denials := tags.deny with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "TAG-001")
	some msg in denials
	contains(msg, "Owner")
}

test_blank_tag_denied if {
	r := fixtures.create("aws_vpc.v", "aws_vpc", {"tags_all": object.union(fixtures.good_tags, {"CostCenter": "  "})})
	denials := tags.deny with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "TAG-001")
}

# With no tags and no default_tags, Terraform leaves tags_all unknown.
# That must still count as untagged (this was a real bug the example caught).
test_untagged_resource_with_unknown_tags_all_denied if {
	r := fixtures.create_unknown("aws_kms_key.k", "aws_kms_key", {"tags": null}, {"tags_all": true})
	denials := tags.deny with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "TAG-001")
}

test_tag_value_unknown_until_apply_is_skipped if {
	r := fixtures.create_unknown("aws_vpc.v", "aws_vpc", {"tags": {"Name": null}}, {"tags_all": true, "tags": {"Name": true}})
	count(tags.deny) == 0 with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
}

test_untaggable_resource_ignored if {
	r := fixtures.create("aws_route.r", "aws_route", {"destination_cidr_block": "0.0.0.0/0"})
	count(tags.deny) == 0 with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
}

test_wrong_environment_tag_denied if {
	r := fixtures.create("aws_vpc.v", "aws_vpc", {"tags_all": object.union(fixtures.good_tags, {"Environment": "dev"})})
	denials := tags.deny with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "TAG-002")
}
