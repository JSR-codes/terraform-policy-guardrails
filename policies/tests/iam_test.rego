package terraform.iam_test

import data.fixtures
import data.terraform.iam
import rego.v1

boundary := "arn:aws:iam::111111111111:policy/boundary"

trust_service := fixtures.policy([{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": "ecs-tasks.amazonaws.com"}}])

role(trust, extra) := fixtures.create("aws_iam_role.r", "aws_iam_role", object.union({"assume_role_policy": trust, "permissions_boundary": boundary}, extra))

test_admin_policy_denied if {
	p := fixtures.create("aws_iam_policy.p", "aws_iam_policy", {"policy": fixtures.policy([{"Effect": "Allow", "Action": "*", "Resource": "*"}])})
	denials := iam.deny with input as fixtures.plan([p])
	fixtures.fired(denials, "IAM-001")
}

test_admin_policy_in_list_form_denied if {
	p := fixtures.create("aws_iam_role_policy.p", "aws_iam_role_policy", {"policy": fixtures.policy([{"Effect": "Allow", "Action": ["s3:GetObject", "*:*"], "Resource": ["*"]}])})
	denials := iam.deny with input as fixtures.plan([p])
	fixtures.fired(denials, "IAM-001")
}

test_deny_star_is_fine if {
	p := fixtures.create("aws_iam_policy.p", "aws_iam_policy", {"policy": fixtures.policy([{"Effect": "Deny", "Action": "*", "Resource": "*"}])})
	count(iam.deny) == 0 with input as fixtures.plan([p])
}

test_scoped_policy_is_fine if {
	p := fixtures.create("aws_iam_policy.p", "aws_iam_policy", {"policy": fixtures.policy([{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}])})
	count(iam.deny) == 0 with input as fixtures.plan([p])
}

test_unknown_policy_is_skipped if {
	p := fixtures.create_unknown("aws_iam_role_policy.p", "aws_iam_role_policy", {}, {"policy": true})
	count(iam.deny) == 0 with input as fixtures.plan([p])
}

test_role_without_boundary_denied if {
	r := fixtures.create("aws_iam_role.r", "aws_iam_role", {"assume_role_policy": trust_service, "permissions_boundary": null})
	denials := iam.deny with input as fixtures.plan([r])
	fixtures.fired(denials, "IAM-002")
}

test_boundary_created_in_same_plan_is_fine if {
	r := fixtures.create_unknown("aws_iam_role.r", "aws_iam_role", {"assume_role_policy": trust_service}, {"permissions_boundary": true})
	count(iam.deny) == 0 with input as fixtures.plan([r])
}

test_trust_anyone_denied if {
	trust := fixtures.policy([{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "*"}}])
	denials := iam.deny with input as fixtures.plan([role(trust, {})])
	fixtures.fired(denials, "IAM-003")
}

test_trust_bare_star_principal_denied if {
	trust := fixtures.policy([{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}])
	denials := iam.deny with input as fixtures.plan([role(trust, {})])
	fixtures.fired(denials, "IAM-003")
}

test_iam_user_and_key_denied if {
	denials := iam.deny with input as fixtures.plan([
		fixtures.create("aws_iam_user.u", "aws_iam_user", {}),
		fixtures.create("aws_iam_access_key.k", "aws_iam_access_key", {}),
	])
	fixtures.fired(denials, "IAM-004")
	count(denials) == 2
}

github := "arn:aws:iam::111111111111:oidc-provider/token.actions.githubusercontent.com"

oidc_trust(condition) := fixtures.policy([{
	"Effect": "Allow",
	"Action": "sts:AssumeRoleWithWebIdentity",
	"Principal": {"Federated": github},
	"Condition": condition,
}])

test_github_trust_pinned_to_environment_passes if {
	trust := oidc_trust({"StringLike": {"token.actions.githubusercontent.com:sub": ["repo:me/app:environment:prod"]}})
	count(iam.deny) == 0 with input as fixtures.plan([role(trust, {})])
}

test_github_trust_without_sub_denied if {
	trust := oidc_trust({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}})
	denials := iam.deny with input as fixtures.plan([role(trust, {})])
	fixtures.fired(denials, "IAM-005")
}

test_github_trust_any_repo_in_org_denied if {
	trust := oidc_trust({"StringLike": {"token.actions.githubusercontent.com:sub": "repo:my-org/*"}})
	denials := iam.deny with input as fixtures.plan([role(trust, {})])
	fixtures.fired(denials, "IAM-005")
}

test_github_trust_star_denied if {
	trust := oidc_trust({"StringLike": {"token.actions.githubusercontent.com:sub": "*"}})
	denials := iam.deny with input as fixtures.plan([role(trust, {})])
	fixtures.fired(denials, "IAM-005")
}
