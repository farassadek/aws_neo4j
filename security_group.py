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


def authorize(conn, group, rule):
    group.authorize(ip_protocol="tcp",from_port=22,to_port=22,cidr_ip="0.0.0.0/0")


def revoke(conn, group, rule):
    if group.rules:
        group.revoke(ip_protocol="tcp",from_port=22,to_port=22,cidr_ip="0.0.0.0/0")


def update_security_group(conn, group, expected_rules):
    revoke(conn, group, expected_rules[0])
    authorize(conn, group, expected_rules[0])

def create_security_groups():
    """
    """

    NEO4J_RULES = [SecurityGroupRule("tcp", "7473", "7474", "0.0.0.0/0", "Neo4j"),SecurityGroupRule("tcp", "22", "22", "0.0.0.0/0", "Neo4j"), ]

    conn = boto.connect_ec2()
    vpcid='vpc-1fa45e7a'	# Develop VPC,  this program van create a sg but line 26 above will complain
    #vpcid='vpc-ff09eb9a'	# Public (default) VPC. This program works ok with the default VPC
    group = get_or_create_security_group(conn, "Neo4j",vpcid)
    update_security_group(conn, group, NEO4J_RULES)


if __name__=="__main__":
    create_security_groups()
