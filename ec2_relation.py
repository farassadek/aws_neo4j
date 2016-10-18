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


    def parse_sg(self,sg_id):
        sgs=boto3.client("ec2", region_name='us-east-1').describe_security_groups()['SecurityGroups']

        sg = boto3.resource("ec2", region_name=self.region).SecurityGroup(sg_id)
        inbound = []
        outbound = []
        for rule in sg.ip_permissions:
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
                inbound.append ((cip,protocol,port_range))

        for rule in sg.ip_permissions_egress:
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
                outbound.append ((cip,protocol,port_range))

        return(inbound,outbound)

    def nodes_relations(self):
        ec2 = boto3.client("ec2", region_name=self.region)                      
        instances = ec2.describe_instances()['Reservations']
        for instance in instances:
            instance_id = instance['Instances'][0]['InstanceId']
            instance_gr = instance['Instances'][0]['SecurityGroups']
            private_ip = instance['Instances'][0]['PrivateIpAddress']
            #public_ip  = instance['Instances'][0]['PublicIpAddress']
            for g in instance_gr:
                    inbound,outbound=self.parse_sg (g['GroupId'])
                    for inb in inbound:
                        rel = (instance_id,inb[0],inb[1],inb[2],'inbound')
                        if not rel in self.relation:
                            self.relation.append(rel)
                    for outb in outbound:
                        rel = (instance_id,outb[0],outb[1],outb[2],'outbound')
                        if not rel in self.relation:
                            self.relation.append(rel)

    def build_nodes(self):
        self.nodes_relations()
        for i in self.relation:
            print (i)
        #rel = self.relation[1]
        #print (rel[1]['Instances'][0]['PrivateIpAddress'])



if __name__  == "__main__" :
    obj = Ec2_Relation()
    obj.build_nodes()

