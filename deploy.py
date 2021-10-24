#!/usr/bin/python3

from pathlib import Path
import os
import sys
import yaml
import subprocess



def create_folder(folder_path):
    isExist = os.path.exists(folder_path)

    if not isExist:
        try:
            os.makedirs(folder_path)
            print("[+] The folder {0} is created!".format(folder_path))
            return True
        except err:
            print("[!] Error: ", err)
            return False
    else:
        print("[+] The folder {0} is exist!".format(folder_path))
        return True



## generate vpc.tf
def generate_vpc_tf(terraform_path):
    contennt = '''
### Create an internet gateway for the VPC, this is required by subnet object ###
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.default.id
}

### Create the VPC subnet to assigned CIDR network (by default, it will change if vpc_cidr_block is set), this is useful when setup AD Lab to make sure IPs are pre-defined ###
resource "aws_vpc" "default" {
  cidr_block           = var.vpc_cidr_block
  enable_dns_hostnames = true
}

### Create subnet 172.16.93.0/24 (by default, will follow vpc_cidr_block) ###
resource "aws_subnet" "tf_lab_subnet" {
  vpc_id                  = aws_vpc.default.id
  cidr_block              = var.vpc_cidr_block
  map_public_ip_on_launch = true

  depends_on = [aws_internet_gateway.gw]
}

### Create route table for the new VPC subnet, and add a default route to internet gateway
resource "aws_default_route_table" "public" {
  default_route_table_id   = aws_vpc.default.main_route_table_id

  tags = {
    Name = "default_route_table"
  }
}

resource "aws_route" "public_internet_gateway" {
  route_table_id            = aws_default_route_table.public.id
  destination_cidr_block    = "0.0.0.0/0"
  gateway_id                = aws_internet_gateway.gw.id

  timeouts {
    create = "5m"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id               = aws_subnet.tf_lab_subnet.id
  route_table_id          = aws_default_route_table.public.id
}
'''

    file_vpc = terraform_path + "/vpc.tf"

    f = open(file_vpc, "w+")
    f.write(contennt)
    f.close()

    print("[+] vpc.tf generated.")



def generate_instance_tf(terraform_path, instances_list):
    file_instance = terraform_path + "/instance.tf"

    file = Path(file_instance)
    file.touch(exist_ok=True)


    for instance in instances_list:
        instance_number = list(instance.keys())[0]
        instance_ostype = instance[instance_number][0]['os_type']
        add_instance_to_ft(instance_number, instance_ostype, file_instance)

    print("[+] instance.tf generated.")



def add_instance_to_ft(instance_number, instance_ostype, file_instance):
    windows_instance = '''
resource "aws_instance" "{0}" {{
  ami                     = var.{0}_ami
  instance_type           = var.instance_type
  key_name                = var.masterkey_name
  get_password_data       = "true"

  private_ip              = var.{0}_private_ip
  subnet_id               = aws_subnet.tf_lab_subnet.id

  vpc_security_group_ids  = [aws_security_group.instancesg.id]
  user_data               = file("../ansibleuserdata.ps1")

  tags = {{
    Name = var.{0}_tagname
  }}
}}
'''
    
    linux_instance = '''
resource "aws_instance" "{0}" {{
  ami                     = var.{0}_ami
  instance_type           = var.instance_type
  key_name                = var.masterkey_name

  private_ip              = var.{0}_private_ip
  subnet_id               = aws_subnet.tf_lab_subnet.id

  vpc_security_group_ids  = [aws_security_group.instancesg.id]

  tags = {{
    Name = var.{0}_tagname
  }}
}}
'''

    content = ''

    if instance_ostype == "windows":
        content = windows_instance.format(instance_number)
    elif instance_ostype == "linux":
        content = linux_instance.format(instance_number)

    f = open(file_instance, "a")
    f.write(content)
    f.close()

    print("[+] {} added.".format(instance_number))




def generate_instancesg_tf(terraform_path, firewall_rules):
    file_instancesg = terraform_path + "/instancesg.tf"

    file = Path(file_instancesg)
    file.touch(exist_ok=True)

    content = '''
resource "aws_security_group" "instancesg" {
  name        = "instance-sg"
  description = "controls access to the instance"
  vpc_id      = aws_vpc.default.id
}


'''

    f = open(file_instancesg, "a")
    f.write(content)
    f.close()

    for rule in firewall_rules:
        add_firewall_rule_to_tf(rule, file_instancesg)
        
    print("[+] instancesg.tf generated.")



def add_firewall_rule_to_tf(rule, file_instancesg):
    tcp_port_content = '''
resource "aws_security_group_rule" "{name}" {{
  security_group_id = aws_security_group.instancesg.id
  type              = "{type}"
  from_port         = {port}
  to_port           = {port}
  protocol          = "{protocol}"
  cidr_blocks       = [{cidr_blocks}]
}}
'''

    rule_number = list(rule.keys())[0]
    rule_name = rule[rule_number][0]['name']
    rule_type = rule[rule_number][1]['type']
    rule_port = rule[rule_number][2]['port']
    rule_protocol = rule[rule_number][3]['protocol']
    cidrblocks_list = []

    for block in rule[rule_number][4]['cidr_blocks'].split(','):
        cidrblocks_list.append('"{0}"'.format(block))

    rule_cidrblocks = ', '.join(cidrblocks_list)

    content = tcp_port_content.format(name=rule_name, type=rule_type, port=rule_port, protocol=rule_protocol, cidr_blocks=rule_cidrblocks)

    f = open(file_instancesg, "a")
    f.write(content)
    f.close()

    print("[+] {} added.".format(rule_name))




def generate_output_tf(terraform_path, instances_list):

    file_output = terraform_path + "/output.tf"

    file = Path(file_output)
    file.touch(exist_ok=True)


    windows_content = '''
### {instance_number} output - Windows

output "{instance_number}_id" {{
  description = "ID of {instance_number}"
  value       = aws_instance.{instance_number}.id
}}

output "{instance_number}_public_ip" {{
  description = "Public IP address of {instance_number}"
  value       = aws_instance.{instance_number}.public_ip
}}

output "{instance_number}_private_ip" {{
  description = "Private IP address of {instance_number}"
  value       = aws_instance.{instance_number}.private_ip
}}

output "{instance_number}_tag_name" {{
  description = "Tag name of {instance_number}"
  value       = aws_instance.{instance_number}.tags.Name
}}

output "{instance_number}_administrator_password" {{
  description = "Get administrator password of {instance_number}"
  value = rsadecrypt(aws_instance.{instance_number}.password_data,file(var.masterkey_path))
}}

'''

    linux_content = '''
### {instance_number} output - Linux

output "{instance_number}_id" {{
  description = "ID of {instance_number}"
  value       = aws_instance.{instance_number}.id
}}

output "{instance_number}_public_ip" {{
  description = "Public IP address of {instance_number}"
  value       = aws_instance.{instance_number}.public_ip
}}

output "{instance_number}_private_ip" {{
  description = "Private IP address of {instance_number}"
  value       = aws_instance.{instance_number}.private_ip
}}

output "{instance_number}_tag_name" {{
  description = "Tag name of {instance_number}"
  value       = aws_instance.{instance_number}.tags.Name
}}

'''

    content = ''

    for instance in instances_list:
        instance_number = list(instance.keys())[0]
        instance_ostype = instance[instance_number][0]['os_type']
        if instance_ostype == "windows":
            content += windows_content.format(instance_number=instance_number)
        elif instance_ostype == "linux":
            content += linux_content.format(instance_number=instance_number)

    f = open(file_output, "a")
    f.write(content)
    f.close()

    print("[+] output.tf generated.")




def generate_variable_tf(terraform_path, dict_config):
    file_variables = terraform_path + "/variables.tf"

    file = Path(file_variables)
    file.touch(exist_ok=True)

    variable_content = '''
variable "{key}"                           {{ default = "{value}"}}
'''

    content = ''

    ## add aws ec2 profile variables
    content += '\n\n## add aws ec2 profile variables\n'
    for tmp in dict_config['aws_ec2_profile']:
        for key, value in tmp.items():
            content += variable_content.format(key=key, value=value)


    ## add network profile variables
    content += '\n\n## add network variables\n'
    for tmp in dict_config['network']:
        for key, value in tmp.items():
            k = 'vpc_cidr_block'
            content += variable_content.format(key=k, value=value)


    ## add instance profile variables
    content += '\n\n## add instance variables\n'
    for tmp in dict_config['instances']:
        for inst_num, inst_config in tmp.items():
            k1 = inst_num + '_ostype'
            v1 = inst_config[0]['os_type']
            content += variable_content.format(key=k1, value=v1)
            k2 = inst_num + '_ami'
            v2 = inst_config[1]['ami']
            content += variable_content.format(key=k2, value=v2)
            k3 = inst_num + '_private_ip'
            v3 = inst_config[2]['private_ip']
            content += variable_content.format(key=k3, value=v3)
            k4 = inst_num + '_tagname'
            v4 = inst_config[3]['hostname']
            content += variable_content.format(key=k4, value=v4)

    
    f = open(file_variables, "a")
    f.write(content)
    f.close()

    print("[+] variables.tf generated.")



def generate_provider_tf(terraform_path, aws_profile_list):
    file_provider = terraform_path + "/provider.tf"

    file = Path(file_provider)
    file.touch(exist_ok=True)

    content = '''
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.27"
    }
  }

  required_version = ">= 0.14.9"
}

'''

    aws_content = '''
provider "aws" {{
  
  # profile = "default"
  region  = "{region}"
}}
'''

    content += aws_content.format(region=aws_profile_list[1]['aws_region'])

    f = open(file_provider, "a")
    f.write(content)
    f.close()

    print("[+] provider.tf generated.")







def generate_playbook_yml(ansible_path, instances_list):

    file_playbook = ansible_path + "/playbook.yml"

    file = Path(file_playbook)
    file.touch(exist_ok=True)

    content = '''
---
- hosts: windows
  roles:
    - common
'''

    role_content = '''
- hosts: {hostname}
  roles:
    - {hostname}
'''

    for instance in instances_list:
        instance_number = list(instance.keys())[0]
        instance_hostname = instance[instance_number][3]['hostname']
        content += role_content.format(hostname=instance_hostname)

    f = open(file_playbook, "a")
    f.write(content)
    f.close()

    print("[+] ansbile playbook.yml generated.")



def generate_inventory_yml(ansible_path, terraform_output_list, ansbile_inventory_list, instances_list, masterkey_path):
    file_inventory = ansible_path + "/inventory/inventory.yml"
    file = Path(file_inventory)
    file.touch(exist_ok=True)


    windows_content = '''{public_ip} ansible_password={admin_pass}\n'''

    linux_content = '''{public_ip} ansible_ssh_user=ubuntu ansible_ssh_private_key_file={masterkey_path} ansible_connection=ssh ansible_port=22\n'''


    content = ''

    for item in ansbile_inventory_list:
        for key,value in item.items():
            content += "\n[{0}]\n".format(key)
            #instances = [x.strip() for x in value.split(',')]
            instances = list(map(str.strip, value.split(',')))
            for inst in instances:
                if list([s for s in instances_list if inst in s][0].values())[0][0]['os_type'] == 'windows':
                    sub = inst + "_public_ip"
                    public_ip = [x.strip() for x in [s for s in terraform_output_list if sub in s][0].split('=')][1].strip('"')
                    sub = inst + "_administrator_password"
                    admin_pass = [x.strip() for x in [s for s in terraform_output_list if sub in s][0].split(' ')][2].strip('"')
                    content += windows_content.format(public_ip=public_ip, admin_pass=admin_pass)

                elif list([s for s in instances_list if inst in s][0].values())[0][0]['os_type'] == 'linux':
                    sub = inst + "_public_ip"
                    public_ip = [x.strip() for x in [s for s in terraform_output_list if sub in s][0].split('=')][1].strip('"')
                    content += linux_content.format(public_ip=public_ip, masterkey_path=masterkey_path)

    f = open(file_inventory, "a")
    f.write(content)
    f.close()

    print("[+] ansible inventory.yml generated.")


def generate_ansilbe_group_vars_all(ansible_path, ansible_vars_all_list):
    file_group_vars = ansible_path + "/group_vars/all"
    file = Path(file_group_vars)
    file.touch(exist_ok=True)

    content = ''

    for item in ansible_vars_all_list:
        for key, value in item.items():
            content += '{0:<50}: {value}\n'.format(key, value=value)


    f = open(file_group_vars, "a")
    f.write(content)
    f.close()

    print("[+] ansible group_vars all generated.")









def main():

    terraform_path = "./lab_terraform"
    ansible_path = "./lab_ansible"

    ## Read in config file
    with open("./initial_config.yml", "r") as stream:
        try:
            dict_config = yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            print(exc)


    instances_list = dict_config['instances']
    firewall_rules = dict_config['firewall_rules']
    aws_profile_list = dict_config['aws_profile']

    ansbile_inventory_list = dict_config['ansible_inventory']
    masterkey_path = list([s for s in dict_config['aws_ec2_profile'] if 'masterkey_path' in s][0].values())[0]
    ansible_vars_all_list = dict_config['ansible_vars_all']


    
    ## create terraform folder
    if create_folder(terraform_path) == False:
        return

    ## generate terraform config files *.tf
    generate_vpc_tf(terraform_path)
    generate_instance_tf(terraform_path, instances_list)
    generate_instancesg_tf(terraform_path, firewall_rules)
    generate_output_tf(terraform_path, instances_list)
    generate_variable_tf(terraform_path, dict_config)
    generate_provider_tf(terraform_path,aws_profile_list)


    ## create ansible folders

    cmd = "mkdir -p {0}/group_vars".format(ansible_path)
    os.system(cmd)
    cmd = "mkdir -p {0}/inventory".format(ansible_path)
    os.system(cmd)
    cmd = "cp -rf pre-ansible/roles {0}/".format(ansible_path)
    os.system(cmd)
  
    generate_playbook_yml(ansible_path, instances_list)


    ## start terraform to create infra
    rst = subprocess.run(['terraform', '-chdir=lab_terraform', 'init'], stdout=subprocess.PIPE)
    
    if str(rst.stdout).find("Terraform has been successfully initialized!"):
        print('[+] Terraform has been successfully initialized!')
        print(rst.stdout.decode('utf-8'))
    else:
        print(rst.stdout.decode('utf-8'))
        return


    rst = subprocess.run(['terraform', '-chdir=lab_terraform', 'validate'], stdout=subprocess.PIPE)
    
    if str(rst.stdout).find("Success!"):
        print("[+] Terraform validation success!")
        print(rst.stdout.decode('utf-8'))
    else:
        print(rst.stdout.decode('utf-8'))
        return


    rst = subprocess.run(['terraform', '-chdir=lab_terraform', 'apply', '--auto-approve'], stdout=subprocess.PIPE)
    
    if str(rst.stdout).find("Apply complete!"):
        print("[+] Terraform apply complete!")
        print(rst.stdout.decode('utf-8'))
    else:
        print(rst.stdout.decode('utf-8'))
        return


    rst = subprocess.run(['terraform', '-chdir=lab_terraform', 'output'], stdout=subprocess.PIPE)
    terraform_output_list = rst.stdout.decode('utf-8').split('\n')
    
    print("[+] Terraform output captured.")

    generate_inventory_yml(ansible_path, terraform_output_list, ansbile_inventory_list, instances_list, masterkey_path)

    generate_ansilbe_group_vars_all(ansible_path, ansible_vars_all_list)


    print("\n[+] All setup, run the following AWS command to make sure all instances are running, check code=16 and all OK:")
    print("aws ec2 describe-instance-status\n")

    print("\n[+] All setup, copy and run the following command to launch ansible configuration:\n")
    print("ANSIBLE_HOST_KEY_CHECKING=False ansible-playbook lab_ansible/playbook.yml -verbose -i lab_ansible/inventory/inventory.yml")







if __name__ == "__main__":
    main()
