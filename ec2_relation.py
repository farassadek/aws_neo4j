from neo4jrestclient.client import GraphDatabase
import boto3

class Ec2_Relation():
    #region = Unicode("us-east-1", config=True, help= """ AWS Region  """)
    gdb = GraphDatabase("http://localhost:7474/db/data/")
    region = 'us-east-1'
    instances = []
    resources = None
    securitygroups = None
    relation = []


    def get_instances (self):
        instances = boto3.client("ec2", region_name=self.region).describe_instances() ['Reservations']
        for instance in instances:
            inst = instance['Instances'][0]
            if not inst.get('State')['Name'] == 'terminated':
                self.instances.append (inst)


    def get_securitygroups (self):
        self.securitygroups=boto3.client("ec2", region_name=self.region).describe_security_groups()['SecurityGroups']

    def get_vpcs (self):
        self.resources=boto3.resource("ec2", region_name=self.region)

    def parse_instances(self):
        inst_sg   = {} 
        inst_nm   = {} 
        prv_inst  = {}
        pub_inst  = {}
        for inst in self.instances:
            iid = inst.get('InstanceId')
            tag = inst.get('Tags')
            igr = inst.get('SecurityGroups')
            ipr = inst.get('PrivateIpAddress')
            ipb = inst.get('PublicIpAddress')
            inst_sg[iid]  = igr
            prv_inst[ipr] = iid
            pub_inst[ipb] = iid
            name = iid
            name = [nm['Value'] for nm in tag if nm['Key'] == 'Name']
            if name:
               name = name[0]
            inst_nm[iid] = name
        return (inst_nm,inst_sg,prv_inst,pub_inst)

        
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
        vpc   = self.resources.Vpc(vpc_id)
        ntag  = vpc.tags[0]['Key']
        vtag  = vpc.tags[0]['Value']
        name = vpc_id
        if ntag == 'Name' and vtag:
            name = vtag
        return (name)


    def build_nodes(self):
        insts_names,insts_sgs,prv_inst,pub_inst = self.parse_instances()
        inbound,outbound,sg_ips = self.parse_securitygroups(prv_inst,pub_inst)
        self.nodes_relations(insts_sgs,inbound,outbound)

        nodes = {}
        for sgip in sg_ips:
            label = self.get_create_label(self.gdb,"ALL_SGs_IPs")
            node = self.gdb.nodes.create(node_id=sgip,name=sgip, title=sgip, public_ip=sgip, private_ip=sgip)
            nodes[sgip] = node
            label.add(node)

        for inst in self.instances:
            iid   = inst.get('InstanceId')
            ivpc  = inst.get('VpcId')
            ipr   = inst.get('PrivateIpAddress')
            ipb   = inst.get('PublicIpAddress')
            label = self.get_create_label(self.gdb,self.get_vpcnsme_vpcid(ivpc))
            node  = self.gdb.nodes.create(node_id=insts_names[iid], name=insts_names[iid], title=insts_names[iid], public_ip=ipb, private_ip=ipr)
            nodes[iid] = node
            label.add(node)


        for rel in self.relation:
            prtcl = rel[2]
            ports = str(rel[3])
            inout = rel[4]
            rname = prtcl + "_" + ports

            if inout == 'inbound':
               #if not rel[1] == 'WWW':
               nodes[rel[1]].relationships.create(rname,nodes[rel[0]], role=rname )
            #else:
            #   nodes[rel[0]].relationships.create(rname,nodes[rel[1]], role=rname )


if __name__  == "__main__" :
    obj = Ec2_Relation()
    obj.get_instances ()
    obj.get_securitygroups ()
    obj.get_vpcs ()
    obj.build_nodes()

