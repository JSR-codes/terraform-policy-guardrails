# METADATA
# title: KMS
# description: Symmetric keys rotate, and deletion has a safety window.
package terraform.kms

import data.terraform.lib
import rego.v1

symmetric(rc) if object.get(lib.after(rc), "customer_master_key_spec", "SYMMETRIC_DEFAULT") == "SYMMETRIC_DEFAULT"

symmetric(rc) if object.get(lib.after(rc), "customer_master_key_spec", "SYMMETRIC_DEFAULT") == null

# KMS-001: rotation on for symmetric keys
violations contains v if {
	some rc in lib.of_type("aws_kms_key")
	symmetric(rc)
	object.get(lib.after(rc), "enable_key_rotation", false) != true
	v := {
		"id": "KMS-001",
		"address": rc.address,
		"msg": "enable_key_rotation must be true",
	}
}

# KMS-002: a deletion window long enough to notice a mistake. Unset means
# AWS's default of 30 days.
deletion_window(rc) := w if {
	w := lib.after(rc).deletion_window_in_days
	is_number(w)
} else := 30

violations contains v if {
	minimum := lib.setting("min_kms_deletion_window_days", 7)
	some rc in lib.of_type("aws_kms_key")
	deletion_window(rc) < minimum
	v := {
		"id": "KMS-002",
		"address": rc.address,
		"msg": sprintf("deletion window is %d days; %s requires at least %d", [deletion_window(rc), lib.environment, minimum]),
	}
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}
