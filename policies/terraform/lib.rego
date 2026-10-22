# Shared helpers for reading `terraform show -json` plan output.
package terraform.lib

import rego.v1

# ---------------------------------------------------------------------------
# Settings (policies/data/env/<env>.yaml is loaded as data.guardrails)
# ---------------------------------------------------------------------------

# Read data.guardrails / data.exceptions directly: reading all of `data`
# would include these policies themselves.
guardrails := g if {
	g := data.guardrails
} else := {}

exception_list := e if {
	e := data.exceptions
} else := []

setting(key, fallback) := object.get(guardrails, key, fallback)

environment := setting("environment", "unknown")

# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

# Every managed resource that will exist after apply (created, updated or
# unchanged). Checking the end state means an old violation can't hide just
# because this change didn't touch it.
resources contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.change.actions != ["delete"]
}

of_type(t) := {rc | some rc in resources; rc.type == t}

after(rc) := object.get(rc.change, "after", {})

unknown(rc, attr) if rc.change.after_unknown[attr] == true

module_of(rc) := object.get(rc, "module_address", "")

index_of(rc) := object.get(rc, "index", null)

# Two resources belong together (e.g. a bucket and its public access block)
# when they name each other directly, or sit in the same module instance with
# the same count/for_each key. IDs are unknown at plan time, so the module
# relationship is the most reliable link available.
linked(subject, partner) if {
	module_of(subject) == module_of(partner)
	index_of(subject) == index_of(partner)
}

linked(subject, partner) if {
	name := after(subject).bucket
	is_string(name)
	after(partner).bucket == name
}

# ---------------------------------------------------------------------------
# IAM policy documents
# ---------------------------------------------------------------------------

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

# Statements from a policy attribute that is a known JSON string.
statements(doc_string) := as_array(doc.Statement) if {
	is_string(doc_string)
	doc := json.unmarshal(doc_string)
}

# ---------------------------------------------------------------------------
# Exceptions (policies/data/exceptions.yaml is loaded as data.exceptions)
# ---------------------------------------------------------------------------

excepted(v) if {
	some e in exception_list
	e.rule == v.id

	# null = no delimiters, so module.data.* covers everything inside that
	# module ([] would default to "." and stop at the next dot)
	glob.match(e.address, null, v.address)
	time.now_ns() < time.parse_rfc3339_ns(e.expires)
}

message(v) := sprintf("[%s] %s: %s", [v.id, v.address, v.msg])
