#!/usr/bin/env python

from neo4jrestclient.client import GraphDatabase
import neo4jrestclient.query
import sys
import itertools
import boto
from boto import ec2
from boto.vpc import VPCConnection

gdb                 = GraphDatabase("http://localhost:7474/db/data/")
region              = 'us-east-1'
conn                = boto.ec2.connect_to_region(region)
sec_groups          = [g for g in conn.get_all_security_groups()]
reservations        = conn.get_all_instances()
instances_list      = []
instances_node_list = []
insts_ip_list       = []
sgs_node_list       = []

# Return vpc name from vpc id.
def get_vpcnsme_vpcid(vpc_id):
    vpc_c   = VPCConnection()
    vpcs    = vpc_c.get_all_vpcs()
    vpc     = [v for v in vpcs if v.id == vpc_id][0]
    name = vpc.id
    if 'Name' in vpc.tags:
        if vpc.tags["Name"]:
            name = vpc.tags["Name"]
    return (name)

# Return all security rules of a security group id.
def get_sg_rules_using_sgid(group_id):
    sg   = [g for g in sec_groups if g.id == group_id][0]
    sgr  = [(r.from_port,r.to_port,r.ip_protocol,r.grants) for r in sg.rules]
    rule = []
    for i in sgr:
        for j in i[3]:
            rule.append((str(i[0]),str(i[1]),str(i[2]),str(j)))
    return (rule)

# Return two lists:
# 1) instances_list: a list of lists of instances.
# 2) insts_ip_list: list of the instances public and private IPs
def get_instanaces (conn):
    reservations    = conn.get_all_instances()
    instances_list  = []
    insts_ip_list   = []
    for reserve in reservations:
        sgs     = []
        instance= reserve.instances[0]
        instid  = str(instance.id)
        nametag = instance.id
        if 'Name' in instance.tags:
            if instance.tags["Name"]:
                nametag = str(instance.tags['Name'])
        vpc     = str(instance.vpc_id)
        pub_ip  = str([instance.ip_address or "NoPublicIP"][0])
        prvt_ip = str(instance.private_ip_address)
        for group in instance.groups:
            sgs.append(get_sg_rules_using_sgid(group.id))
        instances_list.append([instid,nametag,vpc,pub_ip,prvt_ip,sgs])
        insts_ip_list.append(prvt_ip)
        insts_ip_list.append(pub_ip)
        insts_ip_list = list(set(insts_ip_list))
    return(instances_list,insts_ip_list)


# Return all the IPs in the security group.
# For nested security group, return the embeded nested sg name.
def get_all_sg_ips (conn):
    nets = []
    for group in sec_groups:
        for rule in group.rules:
            for grant in rule.grants:
                nets.append(str(grant))
    nets   = list(set(nets))
    return(nets)


# Get the label from label name.
# Crate the label if it is not exists.
def get_create_label (gdb,labelname):
    try:
        label=gdb.labels.get(labelname)
    except:
        label=gdb.labels.create(labelname)
    return(label)


# Create nodes using the instance list from the get_instanaces function above. 
def build_instance_nodes (instances_list):
    instances_node_list=[]
    for inst in instances_list:
        instid  = inst[0]
        nametag = inst[1]
        vpc     = inst[2]
        pub_ip  = inst[3]
        prv_ip  = inst[4]
        label   = get_create_label(gdb,get_vpcnsme_vpcid(vpc))
        node    = gdb.nodes.create(inst_id=instid, name=nametag, title=nametag, public_ip=pub_ip, private_ip=prv_ip)
        label.add(node)
        inst.append(node)
        instances_node_list.append(inst)
    return(instances_node_list)


# Create node from the IPs that in the security group.
# IPs in the SGs that is already build as a node should not be created here.
def build_only_in_sgs_nodes (only_in_sgs):
    sgs_node_list = []
    for sg_ip in only_in_sgs:
        single_node = []
        label   = get_create_label(gdb,"ALL_SGs_IPs")
        node    = gdb.nodes.create(inst_id="NoID",name=sg_ip, title=sg_ip, public_ip=sg_ip, private_ip=sg_ip)
        label.add(node)
	single_node = ["NoID",sg_ip,sg_ip,sg_ip,sg_ip,[] ,node]
	sgs_node_list.append(single_node)
    return(sgs_node_list)


# Create a list of IPs that is in the SG and not in the IPs of instances.
def sgs_ips_minues_insts_ips (sgs_ip_list,insts_ip_list):
    sgs  = set (sgs_ip_list)
    ins  = set ([ins + "/32" for ins in insts_ip_list])
    diff = list ( sgs - ins )
    return (diff)


# Return a node with certain properties.
def search (lable,k,v):
    node=-1
    for node in lable:
        if (node.properties[k]==v):
            return node
    return node


# Call the function to build the nodes. 
def build_nodes(conn):
    (instances_list,insts_ip_list)  =  get_instanaces (conn)
    sgs_ip_list          = get_all_sg_ips(conn)
    only_in_sgs          = sgs_ips_minues_insts_ips (sgs_ip_list,insts_ip_list)
    instances_node_list  = build_instance_nodes (instances_list)
    sgs_node_list        = build_only_in_sgs_nodes (only_in_sgs)
    return ((instances_node_list, sgs_node_list))


# Return the node index given the IP.
def get_node_from_ip (instances_node_list, sgs_node_list , ip):
    ip  = str(ip)
    n1  = [node[6] for node in sgs_node_list if (ip == node[3] or ip == node[4])]
    n2  = [node[6] for node in instances_node_list if (ip == (node[3]+"/32") or ip == (node[4] + "/32"))]
    if (n1):
       return (n1[0])
    else:
       return (n2[0])

# Name the role
def create_role_name(sg):
    (frm,to,prot,ip) = sg
    rname = prot + "_" + frm +"-" + to
    if frm == to:
        rname = prot + "_" + frm
    if frm == "None":
        rname = "AllPorts"
    return rname

# Build the relationship between nodes and the security groups IPs
def build_relation (instances_node_list, sgs_node_list):
    for inl in instances_node_list:
        instid = inl[0]
        name   = inl[1]
        vpc    = inl[2]
        pubip  = inl[3]
        prvip  = inl[4]
        instsg = inl[5] 
        node   = inl[6]
        for sgs in instsg:
            for sg in sgs:
                rname=create_role_name(sg)
                (frm,to,prot,ip) = sg
                rnode = get_node_from_ip (instances_node_list, sgs_node_list , ip)
                rnode.relationships.create(rname , node , role=rname )
    
if __name__ == "__main__":
    (instances_node_list, sgs_node_list) = build_nodes(conn)
    build_relation (instances_node_list, sgs_node_list)


