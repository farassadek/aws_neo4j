from neo4jrestclient.client import GraphDatabase
import boto3
import logging
import time
import threading

class Ec2_Relation():
    #region = Unicode("us-east-1", config=True, help= """ AWS Region  """)
    gdb = GraphDatabase("http://localhost:7474/db/data/")
    region = 'us-east-1'
    relation = []

    def get_instance_by_ip (self,ip):
        ec2 = boto3.client("ec2", region_name=self.region)
        instance = None
        filters = [{ 'Name': 'private-ip-address', 'Values': [ip] }]
        reservations = ec2.describe_instances(Filters=filters)
        if reservations['Reservations']:
            instance_id  = reservations['Reservations'][0]["Instances"][0]["InstanceId"]
            instance = boto3.resource("ec2", region_name=self.region).Instance(instance_id)
        return (instance)

    def parse_instances(self):
        instances=boto3.client("ec2", region_name='us-east-1').describe_instances() ['Reservations']
        inst_sg = {} 
        prv_inst = {}
        pub_inst = {}
        for instance in instances:
            inst = instance['Instances'][0]
            iid = inst.get('InstanceId')
            igr = inst.get('SecurityGroups')
            ipr = inst.get('PrivateIpAddress')
            ipb = inst.get('PublicIpAddress')
            inst_sg[iid]  = igr
            prv_inst[ipr] = iid
            pub_inst[ipb] = iid
        return (inst_sg,prv_inst,pub_inst)

        
    def parse_securitygroups(self,prv_inst,pub_inst):
        sgs=boto3.client("ec2", region_name='us-east-1').describe_security_groups()['SecurityGroups']
        inbound  = {}
        outbound = {}
        for sg in sgs:
            inb  = []
            outb = []
            for rule in sg['IpPermissions']:
                for sg_ip in rule['IpRanges']:
                    port_range ='0 / 65535'
                    protocol = 'All'
                    if not rule['IpProtocol'] == '-1':
                        port_range = rule['FromPort']
                        if not rule['FromPort'] == rule['ToPort']:
                            port_range = str(rule['FromPort']) + ' / ' + str(rule['ToPort'])
                        protocol = rule['IpProtocol']
                    cip = sg_ip['CidrIp']
                    if cip[-2:] == '/0':
                       cip=cip[:-2]
                    if cip[-3:] == '/32':
                       cip=cip[:-3]
                       if prv_inst.get(cip):
                          cip = prv_inst.get(cip)
                       if pub_inst.get(cip):
                          cip = pub_inst.get(cip)
                    inb.append ((cip,protocol,port_range))
            inbound[sg['GroupId']]=inb
            for rule in sg['IpPermissionsEgress']:
                for sg_ip in rule['IpRanges']:
                    port_range ='0 / 65535'
                    protocol = 'All'
                    if not rule['IpProtocol'] == '-1':
                        port_range = rule['FromPort']
                        if not rule['FromPort'] == rule['ToPort']:
                            port_range = str(rule['FromPort']) + ' / ' + str(rule['ToPort'])
                        protocol = rule['IpProtocol']
                    cip = sg_ip['CidrIp']
                    if cip[-2:] == '/0':
                       cip=cip[:-2]
                    if cip[-3:] == '/32':
                       cip=cip[:-3]
                    outb.append ((cip,protocol,port_range))
            outbound[sg['GroupId']]=outb
        return(inbound,outbound)


    def nodes_relations(self):
        insts_sgs,prv_inst,pub_inst = self.parse_instances()
        inbound,outbound = self.parse_securitygroups(prv_inst,pub_inst)
        for iid in insts_sgs.keys():
            for group in insts_sgs[iid]:
                for inb in inbound[group['GroupId']]:
                    rel = (iid,inb[0],inb[1],inb[2],'inbound')
                    if not rel in self.relation:
                        self.relation.append(rel)
                for outb in outbound[group['GroupId']]:
                    rel = (iid,outb[0],outb[1],outb[2],'outbound')
                    if not rel in self.relation:
                        self.relation.append(rel)


    def build_nodes(self):
        self.nodes_relations()
        for i in self.relation:
            print (i)



if __name__  == "__main__" :
    obj = Ec2_Relation()
    obj.nodes_relations()
    obj.build_nodes()

