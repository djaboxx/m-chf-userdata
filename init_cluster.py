#!/usr/bin/env python
import boto3
import subprocess
import shlex
import time
import os
import logging
import urllib
import random
import string
import json
from tempfile import NamedTemporaryFile
import netifaces as ni
import requests
from jinja2 import Template

def aws_lookup():
    resp = requests.get("http://169.254.169.254/latest/dynamic/instance-identity/document")
    j = resp.json()
    return j.get("privateIp")

def interface_lookup(interface):
    ni.ifaddresses(interface)
    return ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
    
def logging_init(loglevel):
    global logger
    logger = logging.getLogger("init-cluster")
    logger.setLevel(loglevel)
    ch = logging.StreamHandler()
    ch.setLevel(loglevel)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

def call(cmd):
    logger.info(cmd)
    p = subprocess.Popen(
        shlex.split(cmd), 
        stderr=subprocess.PIPE, 
        stdout=subprocess.PIPE
    )
    out, err = p.communicate()
    return p.returncode, out, err

def aws_upload(f_path, bucket, key):
    logger.info("uploading {0} to {1}/{2}".format(f_path, bucket, key))
    s3 = boto3.client("s3")
    logger.info(
        "s3.upload_file({0}, {1}, {2})".format(
            f_path, 
            bucket, 
            os.path.join(
                key, 
                os.path.basename(f_path)
            )
        )
    )
    s3.upload_file(
        f_path, 
        bucket, 
        os.path.join(
            key, 
            os.path.basename(f_path)
        )
    )

def aws_download(f_path, bucket, key):
    logger.info("downloading {0} from {1}/{2}".format(f_path, bucket, key))
    s3 = boto3.client("s3")
    logger.info(
        "s3.download_file({0}, {1}, {2})".format(
            bucket,
            os.path.join(
                key, 
                os.path.basename(f_path)
            ),
            f_path
        )
    )
    s3.download_file(
        bucket, 
        os.path.join(
            key, 
            os.path.basename(f_path)
        ),
        f_path
    )

def create_cluster(chef_config_bucket, chef_config_path):
    '''
    function create_cluster {
        chef-backend-ctl create-cluster --accept-license --quiet -y
    }
    '''
    r, o, e = call("chef-backend-ctl create-cluster --accept-license --quiet -y")
    aws_upload(
        "/etc/chef-backend/chef-backend-secrets.json", 
        chef_config_bucket,
        chef_config_path
    )
    return r

def join_cluster(cluster_ip, chef_config_bucket, chef_config_path):
    '''
    function join_cluster {
        chef-backend-ctl join-cluster ${1} --accept-license -s /tmp/chef-backend-secrets.json -y --quiet
    }
    '''
    aws_download("/tmp/chef-backend-secrets.json", chef_config_bucket, chef_config_path)
    r,o,e = call("chef-backend-ctl join-cluster {0} --accept-license -s /tmp/chef-backend-secrets.json -y --quiet".format(cluster_ip))
    os.unlink("/tmp/chef-backend-secrets.json")
    return r
    

def pre_install(hostname):
    global chef_install_path 
    chef_install_path = "{0}/chef-install.sh".format(os.getcwd())
    call("apt-get update")
    call("apt install -y ntp python-pip")
    call("apt-get install -y openjdk-8-jdk")
    call("apt-get install -y rubygems ruby-dev")
    call("hostname {0}".format(hostname))
    call("hostnamectl set-hostname {0}".format(hostname))

    with open("/etc/hostname", "w") as h_file:
        h_file.write("{0}\n".format(hostname))

    urllib.request.urlretrieve(
        "https://omnitruck.chef.io/install.sh", 
        chef_install_path
    )
    


def install_backend(version, node_ip, auth_cidr_addresses):
    call("bash {0} -s -- -P chef-backend -d /tmp -v {1}".format(chef_install_path, version))
    with open("/etc/chef-backend/chef-backend.rb", "a") as cb:
        cb.write('publish_address "{0}"\n'.format(node_ip))
        cb.write("postgresql.md5_auth_cidr_addresses = [\"samehost\",\"samenet\",\"{0}\"]\n".format(auth_cidr_addresses))
   

def install_frontend(version, node_name, chef_config_bucket, chef_config_path):
    call("bash {0} -s -- -P chef-server -d /tmp -v {1}".format(chef_install_path, version))
    server_config = call("chef-backend-ctl gen-server-config {0}".format(node_name))[1]
    with open("/etc/opscode/chef-server.rb", "w") as cs:
        cs.write(str(server_config, 'utf-8'))
        cs.write("\n")
        cs.write("haproxy['local_postgresql_port'] = 5433\n")
        cs.write("haproxy['local_elasticsearch_port'] = 9201\n")

    while call("chef-server-ctl reconfigure")[0] != 0:
        print("Could Not Complete chef-server-ctl configure")
        time.sleep(30)

    aws_upload(
        "/etc/opscode/private-chef-secrets.json",
        chef_config_bucket,
        chef_config_path
    )

    aws_upload(
        "/var/opt/opscode/upgrades/migration-level",
        chef_config_bucket,
        chef_config_path
    )

def install_chef_manage():
    try:
        os.mkdir("/etc/chef/")
    except:
        pass

    call("chef-server-ctl install chef-manage")
    call("chef-server-ctl reconfigure --accept-license --quiet -y")
    call("chef-manage-ctl reconfigure --accept-license --quiet -y")


def install_chef_automate(node_name, domain, automate_license, chef_config_bucket, chef_config_path):
    urllib.request.urlretrieve(
        "https://packages.chef.io/files/current/automate/latest/chef-automate_linux_amd64.zip", 
        "/tmp/chef-automate_linux_amd64.zip"
    )
    call("unzip chef-automate_linux_amd64.zip -d /usr/local/bin")
    with open("/etc/sysctl.conf", "a") as sysctl:
        sysctl.write("vm.max_map_count=262144\n")
        sysctl.write("vm.dirty_expire_centisecs=20000\n")
    call("sysctl -p /etc/sysctl.conf")
    call("chef-automate init-config --fqdn {0}.{1}".format(
        node_name,
        domain
    ))
    call("chef-automate deploy --channel current --upgrade-strategy none --accept-terms-and-mlsa config.toml")
    call('chef-automate license apply "{0}"'.format(automate_license))
    call("chef-automate admin-token | tee /tmp/data-collector.token")
    aws_upload(
        "/tmp/data-collector.token",
        chef_config_bucket,
        chef_config_path
    )



def configure_data_collector(api_token, automate):
    call("chef-server-ctl set-secret data_collector token '{0}'".format(api_token))
    call("chef-server-ctl restart nginx")
    call("chef-server-ctl restart opscode-erchef")
    t = Template('''
    data_collector['root_url'] = 'https://{{ automate }}/data-collector/v0/'
    # Add for chef client run forwarding
    data_collector['proxy'] = true
    # Add for compliance scanning
    profiles['root_url'] = 'https://{{ automate }}'
    ''')
    with open("/etc/opscode/chef-server.rb", "a") as chef_server:
        chef_server.write(
            t.render(automate=automate)
        )

def add_org_admin(org, email, password, chef_config_bucket, chef_config_path):
    call("chef-server-ctl org-create {0} {0} --filename /etc/chef/{0}.pem".format(org))
    call("chef-server-ctl user-create admin chef admin {0} {1} --filename /etc/chef/admin.pem".format(email, password))
    call("chef-server-ctl org-user-add --admin  {0} admin".format(org))
    aws_upload("/etc/chef/{0}.pem".format(org), chef_config_bucket, chef_config_path)
    aws_upload("/etc/chef/admin.pem", chef_config_bucket, chef_config_path)
    with NamedTemporaryFile(mode="w", delete=False) as ntf:
        ntf.write(
            json.dumps(
                dict(
                    email=email,
                    password=password
                ),
                separators=(',', ':'),
                indent=4,
                sort_keys=True
            )
        )
    os.rename(ntf.name, "{0}/credentials.json".format(os.getcwd()))
    aws_upload(
        "{0}/credentials.json".format(os.getcwd()), 
        chef_config_bucket,
        chef_config_path
    )
    os.unlink("{0}/credentials.json".format(os.getcwd()))
    # logger.info("Chef Manage Password: {0}".format(password))

def main(opt):
    logging_init(opt.loglevel)
    pre_install(opt.node_name)

    if opt.node_ip:
        node_ip = opt.node_ip

    if opt.aws:
        node_ip = aws_lookup()

    elif opt.interface:
        node_ip = interface_lookup(opt.interface)

    install_backend(
        opt.backend_version, 
        node_ip, 
        opt.auth_cidr_addresses
    
    )

    if opt.create_cluster:
        while create_cluster(opt.chef_config_bucket, opt.chef_config_path) != 0:
            print("Could not create cluster")
            time.sleep(30)
    
    if opt.join_cluster:
        while join_cluster(opt.join_cluster, opt.chef_config_bucket, opt.chef_config_path) != 0:
            print("Could not join cluster")
            time.sleep(30)

    #if opt.join_cluster:
    #    secrets_path = "{0}/chef-backend-secrets.json".format(opt.chef_config_path)
    #    join_cluster(opt.cluster_ip, opt.chef_config_bucket, secrets_path)

    install_frontend(
        opt.frontend_version, 
        opt.node_name, 
        opt.chef_config_bucket, 
        opt.chef_config_path
    )

    if opt.install_chef_manage:
        install_chef_manage()

    add_org_admin(opt.org,
            opt.email,
            opt.password,
            opt.chef_config_bucket, 
            opt.chef_config_path
        )

    configure_data_collector(
        opt.api_token,
        opt.automate
    )

# bash install_frontend.sh darnold-ubuntu 12.19.31
if __name__ == '__main__':
    '''
    set -Eeu
    node_name=${1}
    chef_backend_version=${2}
    chef_frontend_version=${3}
    private_ip=${4}
    cidr_block=${5}

    chef_config_bucket=${6}
    chef_config_path=${7}
    '''
    from optparse import OptionParser, OptionGroup
    parser = OptionParser()
    parser.add_option("--bucket", dest="chef_config_bucket")
    parser.add_option("--path", dest="chef_config_path")
    parser.add_option("-f", "--frontend", dest="frontend_version")
    parser.add_option("-n", "--node", dest="node_name")
    parser.add_option("--domain", dest="domain")
    parser.add_option("-b", "--backend", dest="backend_version")
    parser.add_option("-c", "--auth-cidr-addresses", dest="auth_cidr_addresses")
    parser.add_option("-l", "--loglevel", dest="loglevel", default="INFO")

    cluster = OptionGroup(parser, "Cluster Options")
    cluster.add_option("--create", dest="create_cluster", action="store_true", default=False)
    cluster.add_option("--join", dest="join_cluster")
    parser.add_option_group(cluster)

    collector = OptionGroup(parser, "Data Collector Options")
    collector.add_option("--token", dest="api_token")
    collector.add_option("--automate")
    parser.add_option_group(collector)

    network = OptionGroup(parser, "Networking Options")
    network.add_option("-d", "--dev", dest="interface", help="Specify TCP Networking Interface")
    network.add_option("-i", "--node-ip", dest="node_ip")
    network.add_option("-a", "--aws", 
        dest="aws", 
        help="Instance is running in AWS. Metadata service is available",
        action="store_true",
        default=False
    )
    parser.add_option_group(network)
    
    manage = OptionGroup(parser, "Chef Manage Options")
    manage.add_option("-m", "--manage", dest="install_chef_manage", action="store_true", default=False)
    manage.add_option("-o", "--org", help="Specify Chef Manage Organization")
    manage.add_option("-e", "--email", help="Specify Chef Manage Admin Email")
    manage.add_option("-p", "--password", help="Specify Chef Manage Admin Password")
    parser.add_option_group(manage)
    opt, arg = parser.parse_args()
    main(opt)
