# METADATA
# title: IAM
# description: No admin wildcards, no users or keys, boundaries on every role, tight trust.
package terraform.iam

import data.terraform.lib
import rego.v1

# Resource types whose `policy` attribute is an identity policy
identity_policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

wildcard_actions := {"*", "*:*"}

# IAM-001: no Allow on every action for every resource
violations contains v if {
	some rc in lib.resources
	rc.type in identity_policy_types
	some st in lib.statements(lib.after(rc).policy)
	st.Effect == "Allow"
	some action in lib.as_array(object.get(st, "Action", []))
	action in wildcard_actions
	some resource in lib.as_array(object.get(st, "Resource", []))
	resource == "*"
	v := {
		"id": "IAM-001",
		"address": rc.address,
		"msg": "policy allows every action on every resource; grant specific actions instead",
	}
}

# IAM-002: every role carries a permissions boundary. An unknown value is
# fine: it means the boundary ARN is created in the same plan.
has_boundary(rc) if lib.unknown(rc, "permissions_boundary")

has_boundary(rc) if {
	b := lib.after(rc).permissions_boundary
	is_string(b)
	b != ""
}

violations contains v if {
	some rc in lib.of_type("aws_iam_role")
	not has_boundary(rc)
	v := {
		"id": "IAM-002",
		"address": rc.address,
		"msg": "role has no permissions_boundary",
	}
}

# IAM-003: trust policies never trust everyone
wildcard_principal(p) if p == "*"

wildcard_principal(p) if {
	some key in ["AWS", "Federated", "Service"]
	"*" in lib.as_array(object.get(p, key, []))
}

violations contains v if {
	some rc in lib.of_type("aws_iam_role")
	some st in lib.statements(lib.after(rc).assume_role_policy)
	st.Effect == "Allow"
	wildcard_principal(st.Principal)
	v := {
		"id": "IAM-003",
		"address": rc.address,
		"msg": "trust policy allows any principal to assume this role",
	}
}

# IAM-004: humans use SSO roles, not IAM users or long-lived keys
violations contains v if {
	some rc in lib.resources
	rc.type in {"aws_iam_user", "aws_iam_access_key", "aws_iam_user_login_profile"}
	v := {
		"id": "IAM-004",
		"address": rc.address,
		"msg": sprintf("%s creates long-lived credentials; use IAM Identity Center or roles", [rc.type]),
	}
}

# IAM-005: GitHub OIDC trust must pin the repository (and ideally branch or
# environment). Without a sub condition, any repo on GitHub can assume it.
github_host := "token.actions.githubusercontent.com"

github_subjects(st) := subjects if {
	cond := object.get(st, "Condition", {})
	subjects := [s |
		some op in ["StringLike", "StringEquals"]
		some s in lib.as_array(object.get(object.get(cond, op, {}), sprintf("%s:sub", [github_host]), []))
	]
}

weak_subject(s) if s in {"*", "repo:*"}

weak_subject(s) if startswith(s, "*")

weak_subject(s) if regex.match(`^repo:[^/]+/\*`, s)

violations contains v if {
	some rc in lib.of_type("aws_iam_role")
	some st in lib.statements(lib.after(rc).assume_role_policy)
	some fed in lib.as_array(object.get(object.get(st, "Principal", {}), "Federated", []))
	contains(fed, github_host)
	subjects := github_subjects(st)
	reason := weak_reason(subjects)
	v := {
		"id": "IAM-005",
		"address": rc.address,
		"msg": sprintf("GitHub OIDC trust %s", [reason]),
	}
}

weak_reason(subjects) := "has no sub condition, so any GitHub repo can assume it" if {
	count(subjects) == 0
}

weak_reason(subjects) := sprintf("uses wildcard subject %q", [s]) if {
	some s in subjects
	weak_subject(s)
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}
