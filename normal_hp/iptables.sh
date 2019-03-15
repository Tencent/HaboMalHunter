#!/bin/sh

# Tencent is pleased to support the open source community by making HaboMalHunter available.
# Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
# Licensed under the MIT License (the "License"); you may not use this file except in 
# compliance with the License. You may obtain a copy of the License at
# 
# http://opensource.org/licenses/MIT
# 
# Unless required by applicable law or agreed to in writing, software distributed under the 
# License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
# either express or implied. See the License for the specific language governing permissions 
# and limitations under the License.

#Author: 
#Date:	March 15, 2019

#iptables -D INPUT -p udp -m udp --dport 54 -j NFQUEUE --queue-num 1
#iptables -D INPUT -p tcp -m tcp --dport 54 -j NFQUEUE --queue-num 1
#iptables -I INPUT -p icmp -j NFQUEUE

#iptables -D INPUT -i eth0 -p tcp -m set --match-set rports dst -j NFQUEUE --queue-num 1 
#iptables -D INPUT -i eth0 -p tcp --tcp-flags FIN,SYN,RST,ACK,PSH SYN  -j NFQUEUE --queue-num 1
#iptables -D INPUT -i eth0 -p tcp --tcp-flags FIN,SYN,RST,ACK,PSH PSH  -j NFQUEUE --queue-num 1
iptables -I INPUT -i eth0 -p tcp  -m set --match-set rports dst -j NFQUEUE --queue-num 1 

