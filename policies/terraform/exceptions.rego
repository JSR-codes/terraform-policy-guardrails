# METADATA
# title: Exception hygiene
# description: Waivers are justified, approved and short-lived.
package terraform.exceptions

import data.terraform.lib
import rego.v1

max_days := lib.setting("max_exception_days", 90)

required_fields := ["rule", "address", "reason", "approved_by", "expires"]

day_ns := ((24 * 60) * 60) * 1000000000

# EXC-001: every field filled in
deny contains msg if {
	some i, e in lib.exception_list
	missing := [f | some f in required_fields; trim_space(sprintf("%v", [object.get(e, f, "")])) == ""]
	count(missing) > 0
	msg := sprintf("[EXC-001] exceptions[%d]: missing %v", [i, missing])
}

# EXC-002: no open-ended waivers
deny contains msg if {
	some i, e in lib.exception_list
	expires := time.parse_rfc3339_ns(e.expires)
	expires - time.now_ns() > max_days * day_ns
	msg := sprintf("[EXC-002] exceptions[%d] (%s on %s): expires more than %d days out; renew it instead", [i, e.rule, e.address, max_days])
}

# Expired waivers stop applying on their own; remind people to clean up.
warn contains msg if {
	some i, e in lib.exception_list
	time.parse_rfc3339_ns(e.expires) <= time.now_ns()
	msg := sprintf("[EXC-003] exceptions[%d] (%s on %s) expired on %s; remove it", [i, e.rule, e.address, e.expires])
}
