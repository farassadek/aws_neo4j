#!/usr/bin/env python
"""
Creating, Get, and Updating security groups.

"""

import collections
import boto

SecurityGroupRule = collections.namedtuple("SecurityGroupRule", ["ip_protocol", "from_port", "to_port", "cidr_ip", "src_group_name"])


def get_or_create_security_group(conn, group_name ,vpcid):
    """
    """
    groups = [g for g in conn.get_all_security_groups() if g.name == group_name]
    group = groups[0] if groups else None
    if not group:
        group = conn.create_security_group(group_name, "A group for %s"%(group_name,),vpcid)
    return group


def modify_sg(conn, group, rule, authorize=False, revoke=False):
    src_group = None
    if rule.src_group_name:
        src_group = conn.get_all_security_groups([rule.src_group_name,])[0]  #<-- This works only with the default VPC

    if authorize and not revoke:
        print "Authorizing missing rule %s..."%(rule,)
        group.authorize(ip_protocol=rule.ip_protocol,
                        from_port=rule.from_port,
                        to_port=rule.to_port,
                        cidr_ip=rule.cidr_ip,
                        src_group=src_group)
    elif not authorize and revoke:
        print "Revoking unexpected rule %s..."%(rule,)
        group.revoke(ip_protocol=rule.ip_protocol,
                     from_port=rule.from_port,
                     to_port=rule.to_port,
                     cidr_ip=rule.cidr_ip,
                     src_group=src_group)


def authorize(conn, group, rule):
    return modify_sg(conn, group, rule, authorize=True)


def revoke(conn, group, rule):
    return modify_sg(conn, group, rule, revoke=True)


def update_security_group(conn, group, expected_rules):
    """
    """
    print 'Updating group "%s"...'%(group.name,)
    import pprint
    print "Expected Rules:"
    pprint.pprint(expected_rules)

    current_rules = []
    for rule in group.rules:
        if not rule.grants[0].cidr_ip:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              "0.0.0.0/0",
                              rule.grants[0].name)
        else:
            current_rule = SecurityGroupRule(rule.ip_protocol,
                              rule.from_port,
                              rule.to_port,
                              rule.grants[0].cidr_ip,
                              None)

        if current_rule not in expected_rules:
            revoke(conn, group, current_rule)
        else:
            current_rules.append(current_rule)

    print "Current Rules:"
    pprint.pprint(current_rules)

    for rule in expected_rules:
        if rule not in current_rules:
            authorize(conn, group, rule)


def create_security_groups():
    """
    attempts to be idempotent:

    if the sg does not exist create it,
    otherwise just check that the security group contains the rules
    we expect it to contain and updates it if it does not.
    """

    NEO4J_RULES = [SecurityGroupRule("tcp", "7473", "7474", "0.0.0.0/0", "Neo4j"),SecurityGroupRule("tcp", "22", "22", "0.0.0.0/0", "Neo4j"), ]

    conn = boto.connect_ec2()
    #vpcid='vpc-1fa45e7a'	# Develop VPC,  this program van create a sg but line 26 above will complain
    vpcid='vpc-ff09eb9a'	# Public (default) VPC. This program works ok with the default VPC
    group = get_or_create_security_group(conn, "Neo4j",vpcid)
    update_security_group(conn, group, NEO4J_RULES)


if __name__=="__main__":
    create_security_groups()
