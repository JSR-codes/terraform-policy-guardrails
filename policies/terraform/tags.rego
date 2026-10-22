# METADATA
# title: Tagging
# description: Every taggable resource carries the ownership and cost tags.
package terraform.tags

import data.terraform.lib
import rego.v1

default_required := ["Project", "Environment", "Owner", "CostCenter"]

# tags_all = resource tags + provider default_tags. Terraform leaves it
# unknown when there are no tags at all, so fall back to the resource's own
# tags (treating null as none). Only when a tag *value* is genuinely unknown
# until apply do we skip the resource.
tags_of(rc) := t if {
	t := lib.after(rc).tags_all
	is_object(t)
} else := t if {
	t := lib.after(rc).tags
	is_object(t)
} else := {}

tags_partly_unknown(rc) if rc.change.after_unknown.tags == true

tags_partly_unknown(rc) if {
	some value in rc.change.after_unknown.tags
	value == true
}

taggable(rc) if "tags_all" in object.keys(lib.after(rc))

taggable(rc) if lib.unknown(rc, "tags_all")

# TAG-001: required tags present and non-empty
violations contains v if {
	some rc in lib.resources
	taggable(rc)
	not tags_partly_unknown(rc)
	tags := tags_of(rc)
	missing := [t |
		some t in lib.setting("required_tags", default_required)
		trim_space(object.get(tags, t, "")) == ""
	]
	count(missing) > 0
	v := {
		"id": "TAG-001",
		"address": rc.address,
		"msg": sprintf("missing required tags %v", [missing]),
	}
}

# TAG-002: the Environment tag matches the environment being deployed,
# which catches config copied from another env directory.
violations contains v if {
	expected := lib.environment
	expected != "unknown"
	some rc in lib.resources
	tags := tags_of(rc)
	actual := tags.Environment
	actual != expected
	v := {
		"id": "TAG-002",
		"address": rc.address,
		"msg": sprintf("Environment tag is %q but this is the %q environment", [actual, expected]),
	}
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}
