package terraform.network_test

import data.fixtures
import data.terraform.network
import rego.v1

rule(cidr, proto, from, to) := fixtures.create(
	sprintf("aws_vpc_security_group_ingress_rule.r%d", [from]),
	"aws_vpc_security_group_ingress_rule",
	{"cidr_ipv4": cidr, "ip_protocol": proto, "from_port": from, "to_port": to},
)

test_https_from_internet_allowed if {
	count(network.deny) == 0 with input as fixtures.plan([rule("0.0.0.0/0", "tcp", 443, 443)]) with data.guardrails as fixtures.prod
}

test_ssh_from_internet_denied if {
	denials := network.deny with input as fixtures.plan([rule("0.0.0.0/0", "tcp", 22, 22)]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-001")
}

test_ssh_from_private_range_allowed if {
	count(network.deny) == 0 with input as fixtures.plan([rule("10.0.0.0/8", "tcp", 22, 22)]) with data.guardrails as fixtures.prod
}

test_port_range_including_443_denied if {
	denials := network.deny with input as fixtures.plan([rule("0.0.0.0/0", "tcp", 0, 65535)]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-001")
}

test_all_protocols_denied if {
	denials := network.deny with input as fixtures.plan([rule("0.0.0.0/0", "-1", -1, -1)]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-001")
}

test_port_80_allowed_in_dev_but_not_prod if {
	r := [rule("0.0.0.0/0", "tcp", 80, 80)]
	count(network.deny) == 0 with input as fixtures.plan(r) with data.guardrails as fixtures.dev
	denials := network.deny with input as fixtures.plan(r) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-001")
}

test_ipv6_open_denied if {
	r := fixtures.create("aws_vpc_security_group_ingress_rule.v6", "aws_vpc_security_group_ingress_rule", {"cidr_ipv6": "::/0", "ip_protocol": "tcp", "from_port": 3389, "to_port": 3389})
	denials := network.deny with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-001")
}

test_inline_security_group_rule_denied if {
	sg := fixtures.create("aws_security_group.sg", "aws_security_group", {"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "protocol": "tcp", "from_port": 22, "to_port": 22}]})
	denials := network.deny with input as fixtures.plan([sg]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-001")
}

test_legacy_security_group_rule_denied if {
	r := fixtures.create("aws_security_group_rule.r", "aws_security_group_rule", {"type": "ingress", "cidr_blocks": ["0.0.0.0/0"], "protocol": "tcp", "from_port": 3306, "to_port": 3306})
	denials := network.deny with input as fixtures.plan([r]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-001")
}

test_vpc_without_flow_log_denied if {
	vpc := fixtures.create_in("module.vpc", "aws_vpc.this", "aws_vpc", {})
	denials := network.deny with input as fixtures.plan([vpc]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-002")
}

test_vpc_with_flow_log_passes if {
	vpc := fixtures.create_in("module.vpc", "aws_vpc.this", "aws_vpc", {})
	fl := fixtures.create_in("module.vpc", "aws_flow_log.this", "aws_flow_log", {})
	count(network.deny) == 0 with input as fixtures.plan([vpc, fl]) with data.guardrails as fixtures.dev
}

subnet(az) := fixtures.create(sprintf("aws_subnet.%s", [az]), "aws_subnet", {"availability_zone": az})

test_two_azs_fail_prod_minimum if {
	denials := network.deny with input as fixtures.plan([subnet("us-east-1a"), subnet("us-east-1b")]) with data.guardrails as fixtures.prod
	fixtures.fired(denials, "NET-003")
}

test_three_azs_pass_prod if {
	subnets := [subnet("us-east-1a"), subnet("us-east-1b"), subnet("us-east-1c")]
	count(network.deny) == 0 with input as fixtures.plan(subnets) with data.guardrails as fixtures.prod
}
