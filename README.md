
# aws_neo4j

A graph representation of AWS environment to visually trace the connections among EC2 instances and the out side world, neo4j is used to visualize these nodes connections.


# Requirements:

1) AWS Account
2) GateWay machine in AWS with access role to the AWS environement.
3) Neo4j Package
4) Python 
5) Apache server
6) aws_neo4j repository 


# Installation: 

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
browes you EC2 public IP 
browes you EC2 public IP 


