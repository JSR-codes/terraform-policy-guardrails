# METADATA
# title: Regions
# description: Resources only land in approved regions.
package terraform.region

import data.terraform.lib
import rego.v1

allowed := {r | some r in lib.setting("allowed_regions", ["us-east-1"])}

# The region a provider block resolves to: a literal, or a root variable.
provider_region(cfg) := r if {
	r := cfg.expressions.region.constant_value
}

provider_region(cfg) := r if {
	some ref in cfg.expressions.region.references
	startswith(ref, "var.")
	r := input.variables[substring(ref, 4, -1)].value
}

# REG-001: provider configured for an approved region
violations contains v if {
	some key, cfg in input.configuration.provider_config
	cfg.name == "aws"
	region := provider_region(cfg)
	not region in allowed
	v := {
		"id": "REG-001",
		"address": sprintf("provider[%s]", [key]),
		"msg": sprintf("region %q is not approved; allowed: %v", [region, sort(allowed)]),
	}
}

# REG-001: AWS provider v6 lets a single resource override its region
violations contains v if {
	some rc in lib.resources
	region := lib.after(rc).region
	is_string(region)
	not region in allowed
	v := {
		"id": "REG-001",
		"address": rc.address,
		"msg": sprintf("resource targets region %q; allowed: %v", [region, sort(allowed)]),
	}
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}
