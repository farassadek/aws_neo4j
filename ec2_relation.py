from neo4jrestclient.client import GraphDatabase
import boto3

class Ec2_Relation():
    #region = Unicode("us-east-1", config=True, help= """ AWS Region  """)
    gdb = GraphDatabase("http://localhost:7474/db/data/")
    region = 'us-east-1'
    instances = []
    securitygroups = None
    relation = []


    def get_instances (self):
        instances = boto3.client("ec2", region_name='us-east-1').describe_instances() ['Reservations']
        for instance in instances:
            inst = instance['Instances'][0]
            if not inst.get('State')['Name'] == 'terminated':
                self.instances.append (inst)


    def get_securitygroups (self):
        self.securitygroups=boto3.client("ec2", region_name='us-east-1').describe_security_groups()['SecurityGroups']


    def parse_instances(self):
        inst_sg   = {} 
        prv_inst  = {}
        pub_inst  = {}
        for inst in self.instances:
            iid = inst.get('InstanceId')
            igr = inst.get('SecurityGroups')
            ipr = inst.get('PrivateIpAddress')
            ipb = inst.get('PublicIpAddress')
            inst_sg[iid]  = igr
            prv_inst[ipr] = iid
            pub_inst[ipb] = iid
        return (inst_sg,prv_inst,pub_inst)

        
    def parse_securitygroups(self,prv_inst,pub_inst):
        inbound  = {}
        outbound = {}
        sg_ips = set(['WWW'])

        for sg in self.securitygroups:
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
                    if cip == '0.0.0.0/0':
                        cip='WWW'
                    elif cip[-3:] == '/32':
                        cip=cip[:-3]
                        if prv_inst.get(cip):
                            cip = prv_inst.get(cip)
                        elif pub_inst.get(cip):
                            cip = pub_inst.get(cip)
                        else:
                            sg_ips.add(cip)
                    else:
                        sg_ips.add(cip)
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
                    if cip == '0.0.0.0/0':
                        cip='WWW'
                    elif cip[-3:] == '/32':
                        cip=cip[:-3]
                        if prv_inst.get(cip):
                            cip = prv_inst.get(cip)
                        elif pub_inst.get(cip):
                            cip = pub_inst.get(cip)
                        else:
                            sg_ips.add(cip)
                    else:
                        sg_ips.add(cip)
                    outb.append ((cip,protocol,port_range))
            outbound[sg['GroupId']]=outb
        return(inbound,outbound,sg_ips)


    def nodes_relations(self,insts_sgs,inbound,outbound):
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


    def get_create_label (self,gdb,labelname):
        try:
            label=gdb.labels.get(labelname)
        except:
            label=gdb.labels.create(labelname)
        return(label)


    def get_vpcnsme_vpcid(self,vpc_id):
        return(vpc_id)

    def get_vpcnsme_vpcid_old(self,vpc_id):
        vpc_c   = VPCConnection()
        vpcs    = vpc_c.get_all_vpcs()
        vpc     = [v for v in vpcs if v.id == vpc_id][0]
        name = vpc.id
        if 'Name' in vpc.tags:
            if vpc.tags["Name"]:
                name = vpc.tags["Name"]
        return (name)


    def build_node(self):
        insts_sgs,prv_inst,pub_inst = self.parse_instances()
        inbound,outbound,sg_ips = self.parse_securitygroups(prv_inst,pub_inst)
        self.nodes_relations(insts_sgs,inbound,outbound)
        for inst in self.instances:
            iid   = inst.get('InstanceId')
            ivpc  = inst.get('VpcId')
            ipr   = inst.get('PrivateIpAddress')
            ipb   = inst.get('PublicIpAddress')
            label = self.get_create_label(self.gdb,self.get_vpcnsme_vpcid(ivpc))
            node  = self.gdb.nodes.create(node_id=iid, name=iid, title=iid, public_ip=iid, private_ip=iid)
            print ('iid = ', iid, 'and vpc =   ',ivpc)
            #node  = self.gdb.nodes.create(node_id=iid, name=iid, title=iid, public_ip=ipb, private_ip=ipr)
            label.add(node)

    def build_nodes(self):
        insts_sgs,prv_inst,pub_inst = self.parse_instances()
        inbound,outbound,sg_ips = self.parse_securitygroups(prv_inst,pub_inst)
        self.nodes_relations(insts_sgs,inbound,outbound)

        nodes = {}
        for sgip in sg_ips:
            label = self.get_create_label(self.gdb,"ALL_SGs_IPs")
            node = self.gdb.nodes.create(node_id=sgip,name=sgip, title=sgip, public_ip=sgip, private_ip=sgip)
            label.add(node)
            nodes[sgip] = node

        for inst in self.instances:
            iid   = inst.get('InstanceId')
            ivpc  = inst.get('VpcId')
            ipr   = inst.get('PrivateIpAddress')
            ipb   = inst.get('PublicIpAddress')
            label = self.get_create_label(self.gdb,self.get_vpcnsme_vpcid(ivpc))
            node  = self.gdb.nodes.create(node_id=iid, name=iid, title=iid, public_ip=ipb, private_ip=ipr)
            label.add(node)
            nodes[iid] = node

        for nodeid in nodes:
            print (nodeid)
       


if __name__  == "__main__" :
    obj = Ec2_Relation()
    obj.get_instances ()
    obj.get_securitygroups ()
    obj.build_nodes()

