
# aws_neo4j

AWS neo4j
    This is a graph representation of AWS environment to visually trace the connection among EC2 instances and the out side world. And neo4j is used to visualize those node connections.

Why? 
    A security group acts as a virtual firewall that controls the traffic for one or more instances. Those security groups are basically a list of
    text rule that can be accessed from the AWS console or the APIs. Tracing the security group(s) for an instance might be easy to trace, but what
    about a large group of instances each of which associated with a dosen of security group each with a large group of rules? 
    The best way is the graphical UI that provide a visual relationship of the instances amonge them and among the outside worlds.  

Who can use this? 
   Any AWS crdential holder can use this method to visually check the connection and security of the EC2 instances connection.


Requirements:

1) AWS Account
2) GateWay machine in AWS with access role to the AWS environement.
3) Neo4j Package
4) Python 
5) Apache server
6) aws_neo4j repository 


Installation: 

yum update -y && reboot 

yum install python34
curl https://bootstrap.pypa.io/get-pip.py | python3.4
pip install ipython
pip install neo4j-driver
pip install boto3
pip install neo4jrestclient

yum install java

tar xzf /tmp/neo4j-community-3.1.2-unix.tar.gz 
cd neo4j-community-3.1.2/
\# In conf/neo4j.conf replace the localhost with 0.0.0.0/0
./bin/neo4j start
curl http://0.0.0.0:7474/

yum install httpd
systemctl enable httpd
cat > /etc/httpd/conf.d/neo4j.conf  << EOF
<VirtualHost *:*>
    ProxyPreserveHost On
    ProxyPass / http://0.0.0.0:7474/
    ProxyPassReverse / http://0.0.0.0:7474/
    ServerName localhost
</VirtualHost>
EOF

systemctl start httpd

git clone https://github.com/farassadek/aws_neo4j.git
cd aws_neo4j/
chmod ec2_relation.py 
python3 ec2_relation.py 


# Test
Open the machine address in any browser


