# METADATA
# title: S3
# description: Buckets are private, encrypted and versioned.
package terraform.s3

import data.terraform.lib
import rego.v1

buckets := lib.of_type("aws_s3_bucket")

# S3-001: all four public access block settings on
has_full_public_access_block(b) if {
	some p in lib.of_type("aws_s3_bucket_public_access_block")
	lib.linked(b, p)
	a := lib.after(p)
	a.block_public_acls == true
	a.block_public_policy == true
	a.ignore_public_acls == true
	a.restrict_public_buckets == true
}

violations contains v if {
	some b in buckets
	not has_full_public_access_block(b)
	v := {
		"id": "S3-001",
		"address": b.address,
		"msg": "bucket needs a public access block with all four settings true",
	}
}

# S3-002: default encryption, with KMS when the environment requires it
allowed_algorithms := {"aws:kms", "aws:kms:dsse"} if {
	lib.setting("require_kms_for_s3", true)
} else := {"aws:kms", "aws:kms:dsse", "AES256"}

has_encryption(b) if {
	some e in lib.of_type("aws_s3_bucket_server_side_encryption_configuration")
	lib.linked(b, e)
	some r in lib.after(e).rule
	some d in r.apply_server_side_encryption_by_default
	d.sse_algorithm in allowed_algorithms
}

violations contains v if {
	some b in buckets
	not has_encryption(b)
	v := {
		"id": "S3-002",
		"address": b.address,
		"msg": sprintf("bucket needs default encryption using one of %v", [sort(allowed_algorithms)]),
	}
}

# S3-003: versioning enabled
has_versioning(b) if {
	some ver in lib.of_type("aws_s3_bucket_versioning")
	lib.linked(b, ver)
	some c in lib.after(ver).versioning_configuration
	c.status == "Enabled"
}

violations contains v if {
	lib.setting("require_versioning", true)
	some b in buckets
	not has_versioning(b)
	v := {
		"id": "S3-003",
		"address": b.address,
		"msg": "bucket versioning must be Enabled",
	}
}

# S3-004: no public canned ACLs
public_acls := {"public-read", "public-read-write", "authenticated-read"}

violations contains v if {
	some acl in lib.of_type("aws_s3_bucket_acl")
	lib.after(acl).acl in public_acls
	v := {
		"id": "S3-004",
		"address": acl.address,
		"msg": sprintf("canned ACL %q makes objects public", [lib.after(acl).acl]),
	}
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}
