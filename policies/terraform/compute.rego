# METADATA
# title: Compute
# description: Approved instance sizes per environment, IMDSv2 everywhere.
package terraform.compute

import data.terraform.lib
import rego.v1

instance_like := {"aws_instance", "aws_launch_template"}

# EC2-001: instance type on the environment's allow-list
violations contains v if {
	allowed := lib.setting("allowed_instance_types", [])
	count(allowed) > 0
	some rc in lib.resources
	rc.type in instance_like
	t := lib.after(rc).instance_type
	is_string(t)
	not t in allowed
	v := {
		"id": "EC2-001",
		"address": rc.address,
		"msg": sprintf("instance type %q is not allowed in %s; allowed: %v", [t, lib.environment, allowed]),
	}
}

# EC2-002: IMDSv2 only (blocks the SSRF credential-theft path)
imdsv2(rc) if {
	some m in lib.after(rc).metadata_options
	m.http_tokens == "required"
}

violations contains v if {
	some rc in lib.resources
	rc.type in instance_like
	not imdsv2(rc)
	v := {
		"id": "EC2-002",
		"address": rc.address,
		"msg": "metadata_options.http_tokens must be \"required\" (IMDSv2)",
	}
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}
