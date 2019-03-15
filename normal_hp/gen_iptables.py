#!/usr/bin/env python
"""
Tencent is pleased to support the open source community by making HaboMalHunter available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in 
compliance with the License. You may obtain a copy of the License at

http://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software distributed under the 
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. See the License for the specific language governing permissions 
and limitations under the License.
"""
"""
Author: 
Date:	March 15, 2019
"""
# Thanks to original author
#__author__ Alexander Korznikov @nopernik
# https://github.com/nopernik/open-ports-honeypot

import os,sys
import re
from subprocess import check_output

tcp_set_name = 'tcp_ports'
udp_set_name = 'udp_ports'

def get_tcp_ports():
	netstat = check_output('netstat -tan', shell=True)
	lports = re.findall(r'(?<=\:)[0-9]{1,5}\w(?=.+listen)',netstat.lower())
	lports = list(set(lports))
	return lports
def get_udp_ports():
	netstat = check_output('netstat -uan', shell=True)
	lports = re.findall(r'(?<=\:)[0-9]{1,5}',netstat.lower())
	lports = list(set(lports))
	return lports

def add_exclude_ports(set_name, openports):
	print ("create set %s"%(set_name))
	os.system('ipset destroy %s' % set_name)
	os.system('ipset create %s bitmap:port range 1-65535' % set_name)
	os.system('ipset add %s 1-65535' % set_name)

	for port in openports:
		print '[-] Exclude port %s to ipset' % port
		os.system('ipset del %s %s' % (set_name,port))

def do_gen():
	add_exclude_ports(tcp_set_name,get_tcp_ports())
	add_exclude_ports(udp_set_name,get_udp_ports())
	os.system("iptables -I INPUT -i eth0 -p tcp  -m set --match-set %s dst -j NFQUEUE --queue-num 1"%(tcp_set_name))
	os.system("iptables -I INPUT -i eth0 -p udp  -m set --match-set %s dst -j NFQUEUE --queue-num 1"%(udp_set_name))

if __name__ == "__main__":
	do_gen()
