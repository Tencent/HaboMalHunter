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
Date:	August 10, 2016
Description: Linux Malware Analysis System, dynamic analyzer
"""
import os,sys,nfqueue,socket
from scapy.all import *
import logging
import logging.handlers
import gen_iptables
import re
import string

l=logging.getLogger("scapy.runtime")
l.setLevel(logging.ERROR)


conf.verbose = 0
conf.L3socket = L3RawSocket

DEF_QUEUE=1
LOG_FMT = "%(asctime)s %(message)s"

log = logging.getLogger()

def init_log():
	# dir
	file_log_dir = "./log" 
	file_log_name = "normal_hp.log"
	if not os.path.exists(file_log_dir):
		os.mkdir(file_log_dir)

	fmt = logging.Formatter(LOG_FMT)

	# file
	file_log_path = os.path.join( file_log_dir, file_log_name )
	file_handler = logging.handlers.WatchedFileHandler(file_log_path)
	file_handler.setFormatter(fmt)
	log.addHandler(file_handler)

	# Console
	console_handler = logging.StreamHandler()
	console_handler.setFormatter(fmt)
	log.addHandler(console_handler)
	log.setLevel(logging.INFO)
	log.info("Normal Honeypot")

def printable_filter(s):
	printable_set = set(string.printable)
	return filter(lambda x : x in printable_set, s)
	
def reply_udp_echo(pkt):
	ip = IP(dst=pkt[IP].src)
	udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
	udp.payload=pkt[UDP].payload
	send(ip/udp)

def reply_tcp_syn_ack(pkt):
	ip = IP(dst=pkt[IP].src)
	seqNum = pkt[TCP].seq
	ackNum = seqNum+1
	tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags='SA', seq=seqNum, ack=ackNum)
	send(ip/tcp)
		
def pkt_handle(pkt):
	proto = pkt.proto
	is_accept=True
	payload=""
	# select ICMP, UDP and TCP
	if proto in [0x01,0x11,0x06]:
		if proto is 0x01:
			# no reply to ICMP, just log
			# only log PING
			if pkt.type is 8:
				#pkt.show()
				payload = str(pkt[ICMP].payload).strip()
				payload = printable_filter(payload)
				#log.info("[ICMP] %s --> %s , PING"%(pkt[IP].src, pkt[IP].dst))	
		elif proto is 0x11:
			payload = str(pkt[UDP].payload).strip()
			payload = printable_filter(payload)
			if pkt[UDP].sport >=1024:
				log.info("[UDP] %s:%d --> %s:%d , #%s#"%(pkt[IP].src, pkt[UDP].sport, pkt[IP].dst, pkt[UDP].dport, payload))
				reply_udp_echo(pkt)		
				# reply to UDP, so drop the pkt
				is_accept=False
		elif proto is 0x06:
			#pkt.show()
			payload = str(pkt[TCP].payload).strip()
			#payload = re.escape(payload)
			payload = printable_filter(payload)
			is_printable = False
			# SYN: reply SYN+ACK, so drop the pkg
			# ACK: log , so accept the pkg(default), the kernel will rst it later
			if 'S' == pkt[TCP].flags :
				reply_tcp_syn_ack(pkt)
				is_accept = False
				is_printable = True
			if 'P' in  str(pkt[TCP].flags) :
				# exclude reply msg, such as remote_ip:80
				if pkt[TCP].sport >= 1024: 
					is_printable = True
			if is_printable:
				log.info("[TCP] %s:%d --> %s:%d , !%s! , #%s#"%(pkt[IP].src, pkt[TCP].sport, pkt[IP].dst, pkt[TCP].dport,str(pkt[TCP].flags), payload))
		else:
			pass	
	return is_accept

def process(payload):
	data = payload.get_data()
	pkt = IP(data)
	#pkt.show() 
	ret = pkt_handle(pkt)
	if ret:
		payload.set_verdict(nfqueue.NF_ACCEPT)
	else:
		payload.set_verdict(nfqueue.NF_DROP)

def main():
	init_log()
	gen_iptables.do_gen()	
	q = nfqueue.queue()
	q.open()
	q.bind(socket.AF_INET)
	q.set_callback(process)
	q.create_queue(DEF_QUEUE)
	log.info("Normal HoneyPot is running on queue %d."%(DEF_QUEUE))
	try:
		q.try_run()
	except KeyboardInterrupt:
		log.info("Exiting...")
		q.unbind(socket.AF_INET)
		q.close()
		sys.exit(0)

if __name__ == '__main__':
	main()
