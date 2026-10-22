# Builders for small fake plans used by the policy unit tests.
package fixtures

import rego.v1

# A resource being created
create(address, rtype, after) := {
	"address": address,
	"mode": "managed",
	"type": rtype,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

# Same, inside a module
create_in(module, address, rtype, after) := object.union(
	create(sprintf("%s.%s", [module, address]), rtype, after),
	{"module_address": module},
)

# A resource with some attributes unknown until apply
create_unknown(address, rtype, after, unknown) := {
	"address": address,
	"mode": "managed",
	"type": rtype,
	"change": {"actions": ["create"], "after": after, "after_unknown": unknown},
}

# A resource being destroyed, or replaced
delete(address, rtype) := {
	"address": address,
	"mode": "managed",
	"type": rtype,
	"change": {"actions": ["delete"], "after": null, "after_unknown": {}},
}

replace(address, rtype) := {
	"address": address,
	"mode": "managed",
	"type": rtype,
	"change": {"actions": ["delete", "create"], "after": {}, "after_unknown": {}},
}

plan(resources) := {"resource_changes": resources}

good_tags := {"Project": "p", "Environment": "prod", "Owner": "o", "CostCenter": "c"}

prod := {
	"environment": "prod",
	"allowed_regions": ["us-east-1"],
	"min_azs": 3,
	"min_kms_deletion_window_days": 30,
	"protect_stateful_resources": true,
	"public_ingress_ports": [443],
	"allowed_instance_types": ["m7i.large"],
}

dev := object.union(prod, {
	"environment": "dev",
	"min_azs": 1,
	"min_kms_deletion_window_days": 7,
	"protect_stateful_resources": false,
	"public_ingress_ports": [80, 443],
	"allowed_instance_types": ["t3.micro"],
})

policy(statements) := json.marshal({"Version": "2012-10-17", "Statement": statements})

# Any denial carrying this rule ID?
fired(denials, id) if {
	some msg in denials
	startswith(msg, sprintf("[%s]", [id]))
}
