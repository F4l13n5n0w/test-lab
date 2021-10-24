#!/usr/bin/python3

import os

## config name_list to put in all lab servers' hostname (those name will be used to generate ansible role folders)
name_list = [
    'common', 
    'avtest' 
    ]


for name in name_list:
    path1 = "pre-ansible/roles/{0}/files".format(name)
    path2 = "pre-ansible/roles/{0}/tasks".format(name)
    path3 = "pre-ansible/roles/{0}/vars".format(name)

    cmd = "mkdir -p {path} && touch {path}/main.yml".format(path=path1)
    os.system(cmd)
    cmd = "mkdir -p {path} && touch {path}/main.yml".format(path=path2)
    os.system(cmd)
    cmd = "mkdir -p {path} && touch {path}/main.yml".format(path=path3)
    os.system(cmd)
