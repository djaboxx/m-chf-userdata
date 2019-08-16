#!/bin/bash
apt-get update
apt-get install -y python3-pip
pip3 install boto3
pip3 install netifaces
pip3 install awscli
pip3 install jinja2
aws s3 cp s3://${chef_config_script} /tmp/init_cluster.py
python3 /tmp/init_cluster.py --bucket=${chef_config_bucket} --path=${chef_config_path} -f ${chef_frontend_version} -b ${chef_backend_version} ${network_option} -c ${auth_cidr} -n ${node_name} ${install_chef_manage} -o ${chef_org} -e ${chef_admin_email} -p ${chef_admin_password} --create --token=${chef_automate_token} --automate=${chef_automate_host}
