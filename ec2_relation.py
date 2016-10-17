import boto3
import logging
import time
import threading

class Ec2_Relation():
    #region = Unicode("us-east-1", config=True, help= """ AWS Region  """) 
    region = 'us-east-1'

    def get_instance_by_ip (self,ip):
        ec2 = boto3.client("ec2", region_name=self.region)
        instance = None
        filters = [{ 'Name': 'private-ip-address', 'Values': [ip] }]
        reservations = ec2.describe_instances(Filters=filters)
        if reservations['Reservations']:
            instance_id  = reservations['Reservations'][0]["Instances"][0]["InstanceId"]
            instance = boto3.resource("ec2", region_name=self.region).Instance(instance_id)
        return (instance)

    def nodes_relations(self):
        ec2 = boto3.client("ec2", region_name=self.region)                      
        instances = ec2.describe_instances()['Reservations']
        for instance in instances:
            instance_id = instance['Instances'][0]['InstanceId']
            instance_gr = instance['Instances'][0]['SecurityGroups']
            print ("---------------------")   
            print (instance_id)                                                    
            print ("........")
            for g in instance_gr:                                                                                   
                print ("..")                 
                print(self.parse_sg (g['GroupId']))
            print ("---------------------")   

    def parse_sg(self,sg_id):
        sg = boto3.resource("ec2", region_name=self.region).SecurityGroup(sg_id)
        inbound = []
        outbound = []
        for rule in sg.ip_permissions:
            for sg_ips in rule['IpRanges']:
                if rule['IpProtocol'] == '-1':
                    inbound.append (('Inbound','All','All','All',sg_ips['CidrIp']))
                else:
                    inbound.append (('Inbound',rule['FromPort'],rule['ToPort'],rule['IpProtocol'],sg_ips['CidrIp']))
        for rule in sg.ip_permissions_egress:
            for sg_ips in rule['IpRanges']:
                if rule['IpProtocol'] == '-1':
                    outbound.append (('Outbound','All','All','All',sg_ips['CidrIp']))
                else:
                    outbound.append (('Outbound',rule['FromPort'],rule['ToPort'],rule['IpProtocol'],sg_ips['CidrIp']))
        return(inbound,outbound)




if __name__  == "__main__" :
    obj = Ec2_Relation()
    obj.nodes_relations()
