
# What is test-lab

```
test-lab is an Terraform / Ansible wrapper for generating a testing lab environment on AWS Cloud environment.
It allows the user to use a single configuration file (initial_config.yml), to spin user designed lab infrastructure, it can be just a single test server (Windows or Linux) or flat network AD-Lab (including DC and domain servers).
```


# How it works

1. Install pre-requirement tools: aws client, ansible client and terraform client, then create and download AWS instance master key file `lab_masterkey.pem` from AWS manager console.
2. Design your test lab, can be a single Windows server for AV/EDR bypass test host, or a Linux VPN server working as a proxy box, or a AD domain with multiple domain-joined servers.
3. Modify the `initial_config.yml` configuration file to match your test lab's network subnet, servers' IP address, hostname, firewall rules etc.
4. Add all instance server's hostname into `name_list` in the `pre-gen.py` and then run it to generate pre-ansible folder.
5. Configure ansible files for each instance as required.
6. Execute `deploy.py` script to deploy the test lab and wait for it ready.



# test-lab file/folder structure

```bash
┌──(root💀kali)-[~/adlab/test-lab]
└─# tree -L 1  
.
├── ansible_examples
├── ansibleuserdata.ps1
├── deploy.py
├── destroy.py
├── initial_config.yml
├── lab_masterkey.pem
└── pre-gen.py
```

### ansibleuserdata.ps1

Download link:

```
https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1
```



