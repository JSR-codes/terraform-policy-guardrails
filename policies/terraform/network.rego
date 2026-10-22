# METADATA
# title: Network
# description: No admin ports open to the internet, flow logs on, enough AZs.
package terraform.network

import data.terraform.lib
import rego.v1

open_cidrs := {"0.0.0.0/0", "::/0"}

# Ports that may face the internet (web traffic only by default)
public_ports := {p | some p in lib.setting("public_ingress_ports", [80, 443])}

# A single TCP port that is on the allow-list
web_only(protocol, from, to) if {
	protocol in {"tcp", "6"}
	from == to
	from in public_ports
}

# Normalised view of every ingress rule, whichever resource type defines it
ingress contains r if {
	some rc in lib.of_type("aws_vpc_security_group_ingress_rule")
	a := lib.after(rc)
	some cidr in [object.get(a, "cidr_ipv4", null), object.get(a, "cidr_ipv6", null)]
	cidr in open_cidrs
	r := {"address": rc.address, "protocol": a.ip_protocol, "from": object.get(a, "from_port", -1), "to": object.get(a, "to_port", -1), "cidr": cidr}
}

ingress contains r if {
	some rc in lib.of_type("aws_security_group")
	some rule in object.get(lib.after(rc), "ingress", [])
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
	r := {"address": rc.address, "protocol": rule.protocol, "from": rule.from_port, "to": rule.to_port, "cidr": cidr}
}

ingress contains r if {
	some rc in lib.of_type("aws_security_group_rule")
	a := lib.after(rc)
	a.type == "ingress"
	some cidr in array.concat(object.get(a, "cidr_blocks", []), object.get(a, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
	r := {"address": rc.address, "protocol": a.protocol, "from": a.from_port, "to": a.to_port, "cidr": cidr}
}

# NET-001: only web ports may be open to the whole internet
violations contains v if {
	some r in ingress
	not web_only(r.protocol, r.from, r.to)
	v := {
		"id": "NET-001",
		"address": r.address,
		"msg": sprintf("%s ports %v-%v open to %s; only %v may face the internet", [r.protocol, r.from, r.to, r.cidr, sort(public_ports)]),
	}
}

# NET-002: every VPC ships flow logs
violations contains v if {
	some vpc in lib.of_type("aws_vpc")
	not has_flow_log(vpc)
	v := {
		"id": "NET-002",
		"address": vpc.address,
		"msg": "VPC has no aws_flow_log in the same module",
	}
}

has_flow_log(vpc) if {
	some fl in lib.of_type("aws_flow_log")
	lib.module_of(fl) == lib.module_of(vpc)
}

# NET-003: subnets spread across enough Availability Zones
violations contains v if {
	minimum := lib.setting("min_azs", 1)
	count(lib.of_type("aws_subnet")) > 0
	azs := {az |
		some s in lib.of_type("aws_subnet")
		az := lib.after(s).availability_zone
		is_string(az)
	}
	count(azs) < minimum
	v := {
		"id": "NET-003",
		"address": "plan",
		"msg": sprintf("subnets span %d AZ(s) %v; %s needs at least %d", [count(azs), sort(azs), lib.environment, minimum]),
	}
}

deny contains msg if {
	some v in violations
	not lib.excepted(v)
	msg := lib.message(v)
}
