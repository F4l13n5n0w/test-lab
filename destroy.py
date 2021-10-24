#!/usr/bin/python3

import os
import sys
import yaml
import subprocess

rst = subprocess.run(['terraform', '-chdir=lab_terraform', 'destroy', '--auto-approve'], stdout=subprocess.PIPE)


file_log = 'output.log'
f = open(file_log, "ab+")
f.write('\n--------\n'.encode('utf-8'))
f.write(rst.stdout)
f.close()


if str(rst.stdout).find("Destroy complete!"):
    print(rst.stdout.decode('utf-8'))
    print("[+] Terraform destroy complete!")

    rst = subprocess.run(['rm', '-rf', 'lab_ansible'], stdout=subprocess.PIPE)
    if rst.stdout.decode('utf-8') != '':
        print(rst.stdout.decode('utf-8'))
    else:
        print("[+] folder lab_ansible has been deleted!")

    rst = subprocess.run(['rm', '-rf', 'lab_terraform'], stdout=subprocess.PIPE)
    if rst.stdout.decode('utf-8') != '':
        print(rst.stdout.decode('utf-8'))
    else:
        print("[+] folder lab_terraform has been deleted!")

    rst = subprocess.run(['rm', '-rf', 'pre-ansible'], stdout=subprocess.PIPE)
    if rst.stdout.decode('utf-8') != '':
    	print(rst.stdout.decode('utf-8'))
    else:
    	print("[+] folder pre-ansible has been deleted!")

    print("[+] Lab destroy succeed!")

else:
    print(rst.stdout.decode('utf-8'))
    print("[!!] Lab destroy failed!")

