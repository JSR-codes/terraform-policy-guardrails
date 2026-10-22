# METADATA
# title: Change safety
# description: Stop accidental deletion of data in protected environments, flag cost surprises.
package terraform.changes

import data.terraform.lib
import rego.v1

stateful_types := {
	"aws_s3_bucket",
	"aws_kms_key",
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_dynamodb_table",
	"aws_efs_file_system",
	"aws_elasticache_replication_group",
}

# Deletes and replacements (replace = delete + create in either order)
destroyed contains rc if {
	some rc in input.resource_changes
	rc.mode == "managed"
	rc.type in stateful_types
	"delete" in rc.change.actions
}

kind(rc) := "replace" if "create" in rc.change.actions

else := "delete"

# CHG-001: stateful resources can't be destroyed where protection is on
violations contains v if {
	lib.setting("protect_stateful_resources", false)
	some rc in destroyed
	v := {
		"id": "CHG-001",
		"address": rc.address,
		"msg": sprintf("plan would %s a stateful %s in %s; do it deliberately with an exception", [kind(rc), rc.type, lib.environment]),
	}
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}

# Elsewhere it's a warning, so reviewers still notice.
warn contains msg if {
	not lib.setting("protect_stateful_resources", false)
	some rc in destroyed
	msg := sprintf("[CHG-001] %s: plan would %s a stateful %s", [rc.address, kind(rc), rc.type])
}

# COST-001: NAT gateways cost ~$32/month each before data charges
warn contains msg if {
	lib.environment == "dev"
	some rc in lib.of_type("aws_nat_gateway")
	"create" in rc.change.actions
	msg := sprintf("[COST-001] %s: NAT gateway in dev costs about $32/month plus data processing", [rc.address])
}
