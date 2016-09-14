#!/bin/python

import sys
import boto
from boto import ec2

region='us-east-1'
conn = boto.ec2.connect_to_region(region)

def print_instanceIDs (conn):
reservations = conn.get_all_instances()
#for reserve in reservations:
reserve = reservations[21]
for instance in reserve.instances:
print(instance.id)
print(instance.tags['Name'])
print_sg(conn,instance)


#group=get_sg(conn, group_name ,vpcid)
def get_sg(conn, group_name ,vpcid):
groups = [g for g in conn.get_all_security_groups() if g.name == group_name]
group = groups[0] if groups else None
return group


def print_sg(conn,instance):
for g in instance.groups:
group_name = g.name
vpcid=""
group=get_sg(conn, group_name ,vpcid)
rules=group.rules
rule0=rules[0]
print(rule0.ip_protocol)
print(rule0.from_port)
print(rule0.to_port)
print(rule0.grants)


print_instanceIDs(conn)

