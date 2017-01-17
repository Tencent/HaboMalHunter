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
import logging
import sys
import time
import json
import subprocess
import signal
import os
import stat
import datetime
import copy
import re
import traceback
import xml.etree.ElementTree as ET

# Custermised Package
sys.path.append("..")
import base
import metrics

class DynamicAnalyzer(base.BaseAnalyzer):
	def __init__(self, cfg):
		base.BaseAnalyzer.__init__(self,cfg)
		self.tag_file = cfg.dynamic_finished_fname
		self.action_list = []
		self.action_info = [] # store the action without sorting
		self.action_cnt = 0
		self.time_info = {}
		
	def start(self):
		try:
			self.log.info("DynamicAnalyzer starts")
			base.BaseAnalyzer.start(self)
			self.add_action(self.create_begin_action())
			if self.cfg.is_executable:
				self.init_ltrace_tpl()
				self.trace_type_decision()
				self.start_net_interface()
				self.add_action(self.create_launch_action())
				self.launch()
				self.post_launch()
				self.parse_monitor_log()
				self.sort_and_add_action()
				self.add_action(self.create_terminate_action())
			else:
				error_msg = "The target can not be executed. add no exe Error report"
				self.log.info(error_msg)
				self.info["error_msg"] = error_msg
				self.add_action(self.create_noexe_action(self.info["error_msg"]))
		except Exception as e:
			self.log.error("dynamic analysis error: %s"%(str(e)))
			self.log.error(traceback.format_exc())
			self.info["error_msg"]=str(e)
			self.add_action(self.create_noexe_action(self.info["error_msg"]))

	def end(self):
		self.log.info("DynamicAnalyzer ends")
		self.merge_Import()
		base.BaseAnalyzer.end(self)

	def start_net_interface(self):
		cmd = ["/sbin/ifup","eth0"]
		output = self.check_output_safe(cmd)
		cmd = ["/sbin/ifup","eth1"]
		output = self.check_output_safe(cmd)
		cmd = ["/sbin/ifconfig"]
		output = self.check_output_safe(cmd)
		time.sleep(1)
		self.log.info("ifconfig: %s",output)

	def parse_monitor_log(self):
		self.process_info()
		self.io_info()
		self.network_info()
		self.ld_info()
		self.trace_info()
		self.syscall_info()

	def syscall_info(self):
		self.action_syscall()

	def trace_info(self):
		if "ltrace" == self.cfg.decided_trace_type:
			self.parse_ltrace()
		else:
			self.parse_strace()

	def is_func_called(self,ctx):
		ret = False
		if 0!=len(ctx):
			first_ch = ctx[0]
			eq_pos = ctx.find("=")
			if (first_ch not in ['+','-','<'] ):
				if -1 != eq_pos:
					ret = True
				unfi_pos = ctx.find("unfinished")
				if -1 != unfi_pos:
					ret = True
		return ret

	def parse_ltrace_func(self,ctx):
		func_name = ""
		func_argstr = ""
		func_ret = -1
		eq_pos = ctx.find("=")
		unfi_pos = ctx.find("unfinished")
		if -1 != eq_pos:
			func_ret = ctx[eq_pos+len("="):].strip()
			quote_pos = ctx.find("(")
			if -1 != quote_pos:
				func_name = ctx[0:quote_pos].strip()
				r_quote_pos = ctx.rfind(")")
				if -1 != r_quote_pos:
					func_argstr = ctx[quote_pos+len("("):r_quote_pos]
					func_argstr = "[%s]"%(func_argstr)
		if -1 != unfi_pos:
			func_ret = "unfinished"
			quote_pos = ctx.find("(")
			if -1 != quote_pos:
				func_name = ctx[0:quote_pos].strip()
				r_quote_pos = ctx.rfind("<unfinished")
				if -1 != r_quote_pos:
					func_argstr = ctx[quote_pos+len("("):r_quote_pos]
					func_argstr = "[%s]"%(func_argstr)
		return (func_name,func_argstr,func_ret)
			
	def init_ltrace_tpl(self):
		ltrace_tpl=[]

		node = {'name':'getpid','ID':metrics.D_ID_LIBC_getpid, 'ID_NOTE':metrics.D_ID_LIBC_getpid_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'printf','ID':metrics.D_ID_LIBC_printf, 'ID_NOTE':metrics.D_ID_LIBC_printf_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'puts','ID': metrics.D_ID_LIBC_puts, 'ID_NOTE':metrics.D_ID_LIBC_puts_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'gethostbyname','ID': metrics.D_ID_LIBC_gethostbyname, 'ID_NOTE':metrics.D_ID_LIBC_gethostbyname_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'bind','ID': metrics.D_ID_LIBC_bind, 'ID_NOTE':metrics.D_ID_LIBC_bind_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'send','ID': metrics.D_ID_LIBC_send, 'ID_NOTE':metrics.D_ID_LIBC_send_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'recv','ID': metrics.D_ID_LIBC_recv, 'ID_NOTE':metrics.D_ID_LIBC_recv_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'remove','ID': metrics.D_ID_LIBC_remove, 'ID_NOTE':metrics.D_ID_LIBC_remove_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'rename','ID': metrics.D_ID_LIBC_rename, 'ID_NOTE':metrics.D_ID_LIBC_rename_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'readdir','ID': metrics.D_ID_LIBC_readdir, 'ID_NOTE':metrics.D_ID_LIBC_readdir_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'dlopen','ID': metrics.D_ID_LIBC_dlopen, 'ID_NOTE':metrics.D_ID_LIBC_dlopen_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'dlsym','ID': metrics.D_ID_LIBC_dlsym, 'ID_NOTE':metrics.D_ID_LIBC_dlsym_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'kill','ID': metrics.D_ID_LIBC_kill, 'ID_NOTE':metrics.D_ID_LIBC_kill_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'listen','ID': metrics.D_ID_LIBC_listen, 'ID_NOTE':metrics.D_ID_LIBC_listen_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'accept','ID': metrics.D_ID_LIBC_accept, 'ID_NOTE':metrics.D_ID_LIBC_accept_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'fork','ID': metrics.D_ID_LIBC_fork, 'ID_NOTE':metrics.D_ID_LIBC_fork_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'wait','ID': metrics.D_ID_LIBC_wait, 'ID_NOTE':metrics.D_ID_LIBC_wait_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'system','ID': metrics.D_ID_LIBC_system, 'ID_NOTE':metrics.D_ID_LIBC_system_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'setsid','ID': metrics.D_ID_LIBC_setsid, 'ID_NOTE':metrics.D_ID_LIBC_setsid_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'dup','ID': metrics.D_ID_LIBC_dup, 'ID_NOTE':metrics.D_ID_LIBC_dup_NOTE}
		ltrace_tpl.append(node)
		node = {'name':'dup2','ID': metrics.D_ID_LIBC_dup2, 'ID_NOTE':metrics.D_ID_LIBC_dup2_NOTE}
		ltrace_tpl.append(node)

		self.info["ltrace_tpl"] = ltrace_tpl

	def search_ltrace_tpl(self, func_name):
		cnt=0
		for node in self.info["ltrace_tpl"]:
			if func_name == node["name"]:
				return cnt
			cnt=cnt+1
		return -1

	def is_func_resumed(self, line):
		parts = line.split()
		if len(parts)>=3:
			pid = parts[0]
			str_ts = parts[1]
			ctx = "".join(parts[2:])
			if ctx.startswith("<...") and -1!=ctx.find("resumed"):
				return True
		return False

	def check_func_by_name(self, line, func_name):
		return -1!=line.find(func_name)

	def get_func_ret(self, line):
		func_ret = "unfinished"
		parts = line.split()
		if len(parts)>=3:
			pid = parts[0]
			str_ts = parts[1]
			ctx = "".join(parts[2:])
			eq_pos = ctx.find("=")
			if -1!=eq_pos:
				func_ret = ctx[eq_pos+len("="):]
				func_ret = func_ret.strip()
		return func_ret

	def handle_ltrace(self, output_list):
		ret = []
		tot_sz = len(output_list)
		cnt=0
		for ind in range(tot_sz):
			if ind > self.cfg.trace_limit:
				self.log.info("trace events are too much. [%d/%d]"%(ind,self.cfg.trace_limit))
				break
			line = output_list[ind]
			parts = line.split()
			if len(parts)>=3:
				pid = parts[0]
				str_ts = parts[1]
				ctx = "".join(parts[2:])
				if self.is_func_called(ctx):
					(func_name,func_argstr,func_ret) = self.parse_ltrace_func(ctx)
					if "unfinished" == func_ret:
						#self.log.info("func_name: %s , unfinished.", func_name)
						for next_ind in range(ind+1, tot_sz):
							next_line = output_list[next_ind]
							#self.log.debug("next_line: #%s#, next_ind", next_line)
							is_resumed = self.is_func_resumed(next_line)
							is_func_by_name = self.check_func_by_name(next_line,func_name)
							#self.log.debug("is_resumed: %r , is_func_by_name: %r",is_resumed, is_func_by_name)
							if is_resumed and is_func_by_name:
								func_ret = self.get_func_ret(next_line)
								#self.log.info("unfinished func: %s, ret:%s", func_name, func_ret)
								break

					if len(func_name):
						if func_name.startswith("SYS_"): # syscall
							#self.log.debug("syscall %s has not been support",func_name)
							pass
						else:
							ind = self.search_ltrace_tpl(func_name)
							#self.log.debug("find func_name: %s, ind: %d",func_name, ind)
							if -1!=ind:
								tpl = self.info["ltrace_tpl"][ind]
								ts = self.parse_time(str_ts)
								str_src = "PID=%s"%(pid)
								str_dst = "%s ret=%s, args=%s "%(func_name,func_ret,func_argstr)
								node = {"ts":ts, 'src':str_src, 'dst':str_dst}
								node["ID"] = tpl["ID"]
								node["ID_NOTE"] = tpl["ID_NOTE"]
								#self.log.info("func_name: %s will be shown", func_name)
								ret.append(node)
							else:
								#self.log.info("func_name: %s is not in ltrace tpl", func_name)
								pass
		return ret

	def parse_ltrace(self):
		log_file = self.info["ltrace_log_path"]
		self.log.info("parsing ltrace data %s",log_file)
		f = open(log_file,"rb")
		output_list = f.readlines()
		f.close()
		data_list = self.handle_ltrace(output_list)
		self.action_info.extend(data_list)

	def parse_strace(self):
		self.log.info("please use sysdig instead of strace")

	def merge_Import(self):
		static_log_file = os.path.join(self.cfg.file_log_dir,self.info["hash_md5"]+".static")
		fi = open(static_log_file,"rb")
		static_info = json.load(fi)
		fi.close()
		static_info["LD_Import"] = self.info.get("ld_symbol",[])
		fo = open(static_log_file,"wb")
		json.dump(static_info, fo, indent=4, sort_keys=False)
		fo.close()
		self.log.info("%d LD_Import info was merged", len(static_info["LD_Import"] ))

	def extract_func(self, line):
		parts = line.split()
		ret = ""
		if len(parts) >=3:
			str_func = parts[2]
			sz = len(str_func)
			ret = str_func[1:sz-1]
		return ret
	def ld_info(self):
		self.info["ld_symbol"]=[]
		if "strace" == self.cfg.decided_trace_type:
			self.log.info("statically linked elf dose not supports LD_INFO")
			return
		else:
			ld_log_path = self.cfg.ld_debug_log_abs+"."+str(self.info["target_pid"])
			if os.path.exists(ld_log_path):
				f = open(ld_log_path,"rb")
				full_list = self.normalise(f.readlines())
				for line in full_list:
					parts = line.split(":")
					if len(parts) >=3:
						mid_part = parts[1].strip()
						if mid_part.startswith("binding"):
							sec_parts = mid_part.split()
							if len(sec_parts) >=6:
								file_from = sec_parts[2].strip()
								file_to = sec_parts[5].strip()
								if os.path.abspath(file_from) == self.cfg.target_abs_path :
									right_part = parts[2].strip()
									func_name = self.extract_func(right_part)
									#self.log.debug("%s to %s with %s",file_from, file_to, func_name)
									node = {"Function":func_name,"ID":metrics.S_ID_LD_IMPORT, "Module":file_to}
									self.info["ld_symbol"].append(node)
			else:
				self.log.error("ld_log can not be found: %s",ld_log_path)

	def process_info(self):
		self.clone_info()
		self.execve_info()
		self.procexit_info()

	def raw_syscall(self, data_list):
		output_list=[]
		# the first one is a placeholder for the lable
		ret_list=[-1]
		for node in data_list:
			str_ts = node["ts"].strftime("%H:%M:%S.%f")
			#self.log.debug("ts:%s , type: %s",str_ts,type(str_ts))
			str_src = node["src"]
			str_dst = node["dst"]
			pos = str_dst.find(":")
			if -1!=pos:
				str_syscall = str_dst[0:pos]
				# -1 means undefined
				syscall_id = metrics.syscall_table.get(str_syscall,-1)
				ret_list.append(syscall_id)
				if -1 == syscall_id:
					self.log.info("syscall %s, id is undefined"%(str_syscall))
				#output = "%s %s # %s"%(str_ts, str_syscall, str_src)
				output = "%s %s=%d # %s"%(str_ts, str_syscall,syscall_id, str_src)
				output_list.append(output)
		ctx="\n".join(output_list)
		fname=self.info["hash_md5"]+".syscall"
		self.write_file(fname,ctx)
		return ret_list

	def action_syscall(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"syscall_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"% (self.info["target_name"],str(self.info["target_pid"]))]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			# start from 3rd, because the first two are always pause,execve
			output_list = output_list[2:]
			data_list = self.handle_sysdig(output_list, metrics.D_ID_SYSCALL_ALL, metrics.D_ID_SYSCALL_ALL_NOTE)
			self.action_info.extend(data_list)
			ret_list = self.raw_syscall(data_list)
			self.add_syscall_seq(ret_list)

	def add_syscall_seq(self, sys_seq_list):
		file_path = self.cfg.target_abs_path
		seq_str = " ".join(str(x) for x in sys_seq_list)
		seq_str = seq_str+" "
		act = [file_path, seq_str, metrics.D_ID_SYSCALL_SEQ, metrics.D_ID_SYSCALL_SEQ_NOTE]
		self.add_action(act)
		#write to file
		fname=self.info["hash_md5"]+".seq.txt"
		self.write_file(fname,seq_str)

	def file_close_info(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"close_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"% (self.info["target_name"],str(self.info["target_pid"]))]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, metrics.D_ID_SYSCALL_CLOSE, metrics.D_ID_SYSCALL_CLOSE_NOTE)
			self.action_info.extend(data_list)

	def file_open_info(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"open_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"% (self.info["target_name"],str(self.info["target_pid"]))]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, metrics.D_ID_SYSCALL_OPEN, metrics.D_ID_SYSCALL_OPEN_NOTE)
			self.action_info.extend(data_list)

	def procexit_info(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"procexit_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"% (self.info["target_name"],str(self.info["target_pid"]))]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, metrics.D_ID_PROC_EXIT, metrics.D_ID_PROC_EXIT_NOTE)
			self.action_info.extend(data_list)

	def execve_info(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"execve_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"% (self.info["target_name"],str(self.info["target_pid"]))]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, metrics.D_ID_SYSCALL_EXECVE, metrics.D_ID_SYSCALL_EXECVE_NOTE)
			self.action_info.extend(data_list)

	def handle_sysdig(self,output_list, act_id, act_id_note):
		ret = []
		for line in output_list:
			parts=[]
			try:
				parts = json.loads(line)
			except ValueError as e:
				self.log.error("format error, will continue: %s",line)
				continue
			str_ts = ""
			str_src =""
			str_dst = ""
			str_comment = ""
			node = {}
			if 3 == len(parts) :
				(str_ts,str_src,str_dst) = parts
				ts = self.parse_time(str_ts)
				node = {"ts":ts, 'src':str_src, 'dst':str_dst}
			elif 4 == len(parts):
				(str_ts,str_src,str_dst, str_comment) = parts
				ts = self.parse_time(str_ts)
				node = {"ts":ts, 'src':str_src, 'dst':str_dst, 'comment':str_comment}
			node["ID"] = act_id
			node["ID_NOTE"] = act_id_note
			#self.log.debug("ts: %s, %s",ts,type(ts))
			ret.append(node)
		return ret

	def clone_info(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"clone_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"% (self.info["target_name"],str(self.info["target_pid"]))]
			output=self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, metrics.D_ID_SYSCALL_CLONE, metrics.D_ID_SYSCALL_CLONE_NOTE)
			self.action_info.extend(data_list)

	def io_info(self):
		self.file_open_info()
		self.file_access_info("read",metrics.D_ID_SYSCALL_READ, metrics.D_ID_SYSCALL_READ_NOTE)
		self.file_access_info("write",metrics.D_ID_SYSCALL_WRITE, metrics.D_ID_SYSCALL_WRITE_NOTE)
		self.file_close_info()
		self.pick_file_info()

	def pick_file_info(self):
		lo_id = metrics.D_ID_SYSCALL_OPEN
		hi_id = metrics.D_ID_FILE_LOCK
		#[lo_id, hi_id]
		path_list=[]
		act_size = len(self.action_info)
		for i in range(act_size):
			node = self.action_info[i]
			if node["ID"] >=lo_id and node["ID"] <=hi_id:
				info_str = node["dst"]
				pos_start = info_str.find("path=")
				pos_end = info_str.find(",")
				if -1!=pos_start and -1!=pos_end:
					path = info_str[pos_start+len("path="):pos_end]
					path_list.append(path)
		path_list = list(set(path_list))
		for p in path_list:
			hash_md5 = "None"
			if os.path.exists(p) and os.path.getsize(p) < 1024*1024 and os.path.isfile(p) and not p.startswith('/dev/'):
				self.log.info("path %s md5"%(p))
				hash_md5 = base.BaseAnalyzer.get_md5_by_fname(p)
			act = ["pick_file path=%s, hash_md5=%s"%(p,hash_md5), p, metrics.D_ID_FILE_PATH_INFO, metrics.D_ID_FILE_PATH_INFO_NOTE]
			self.add_action(act)

	def file_access_info(self, rw_type, act_id, act_id_note):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"access_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s %s"%(self.info["target_name"], str(self.info["target_pid"]), rw_type)]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, act_id, act_id_note)
			self.action_info.extend(data_list)
		
	def socket_info(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"net_socket_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"%(self.info["target_name"], str(self.info["target_pid"]))]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, metrics.D_ID_NET_SOCEKT, metrics.D_ID_NET_SOCEKT_NOTE)
			self.action_info.extend(data_list)

	def connect_info(self):
		plugin_path = os.path.join(self.cfg.sysdig_plugin_dir,"net_connect_info.lua")
		if os.path.exists(plugin_path):
			cmd = ['/usr/bin/sysdig','-r'+self.info["sysdig_log_path"], '-c'+plugin_path, "%s %s"%(self.info["target_name"], str(self.info["target_pid"]))]
			output = self.check_output_safe(cmd)
			output_list = self.normalise(output.splitlines())
			data_list = self.handle_sysdig(output_list, metrics.D_ID_NET_CONNECT, metrics.D_ID_NET_CONNECT_NOTE)
			self.action_info.extend(data_list)

	def combain_src_dest(self, node):
		node["dst"] = node["src"]+" -> "+node["dst"]
		return node

	def handle_dns(self, output_list):
		ret=[]
		for line in output_list:
			parts_dir = line.split("->")
			if len(parts_dir) >=2:
				parts_src = parts_dir[0].split()
				if len(parts_src)>=3:
					ts_info = parts_src[1].strip()
					src_info = parts_src[2].strip()
					dest_info = parts_dir[1].strip()
					ts=self.parse_time(ts_info)
					node = {"ts":ts, "src":src_info, "dst":dest_info}
					if self.is_pure_protocal(dest_info,"DNS"):
						if -1 == dest_info.find("response"):
							node["ID"] = metrics.D_ID_NET_DNS_QUERY
							node["ID_NOTE"] = metrics.D_ID_NET_DNS_QUERY_NOTE
						else:
							node["ID"] = metrics.D_ID_NET_DNS_RESPONSE
							node["ID_NOTE"] = metrics.D_ID_NET_DNS_RESPONSE_NOTE
						node = self.combain_src_dest(node)
						ret.append(node)
		return ret

	def dns_info(self):
		cmd = ['/usr/bin/tshark', '-n', '-ta', '-r'+ self.info["tcpdump_log_path"], '-2', '-R', 'dns.qry.name']
		self.log.info("dns cmd: %s",str(cmd))
		output = self.check_output_safe(cmd)
		output_list = self.normalise(output.splitlines())
		data_list = self.handle_dns(output_list)
		self.action_info.extend(data_list)

	def http_is_send(self, dest_info):
		parts = dest_info.split()
		if len(parts)>=4:
			method = parts[3].strip()
			method = method.upper()
			if method in ['OPTIONS','GET','HEAD','POST','PUT','DELETE','TRACE','CONNECT']:
				return True
		return False

	def handle_http(self, output_list):
		ret=[]
		for line in output_list:
			parts_dir = line.split("->")
			if len(parts_dir) >=2:
				parts_src = parts_dir[0].split()
				if len(parts_src)>=3:
					ts_info = parts_src[1].strip()
					src_info = parts_src[2].strip()
					dest_info = parts_dir[1].strip()
					ts=self.parse_time(ts_info)
					node = {"ts":ts, "src":src_info, "dst":dest_info}
					if self.is_pure_protocal(dest_info,"HTTP"):
						if self.http_is_send(dest_info):
							node["ID"] = metrics.D_ID_NET_HTTP_SEND
							node["ID_NOTE"] = metrics.D_ID_NET_HTTP_SEND_NOTE
							self.log.debug("++++ HTTP send: +++: %s",str(node))
						else:
							node["ID"] = metrics.D_ID_NET_HTTP_RESPONSE
							node["ID_NOTE"] = metrics.D_ID_NET_HTTP_RESPONSE_NOTE
						node = self.combain_src_dest(node)
						ret.append(node)
		return ret

	def http_info(self):
		cmd = ['/usr/bin/tshark', '-n', '-ta', '-r'+ self.info["tcpdump_log_path"], 'http']
		output = self.check_output_safe(cmd)
		output_list = self.normalise(output.splitlines())
		data_list = self.handle_http(output_list)
		self.log.info("http_info: %s",str(data_list))
		self.action_info.extend(data_list)

	def is_pure_protocal(self, dest_info, protocal_str):
		"""
		parts = dest_info.split()
		if len(parts)>=1:
			protocal = parts[1].strip()
			protocal = protocal.upper()
			if protocal.startswith(protocal_str):
				return True
		return False
		"""
		return (-1!=dest_info.find(protocal_str))

	def handle_tcp(self, output_list):
		ret=[]
		for line in output_list:
			parts_dir = line.split("->")
			if len(parts_dir) >=2:
				parts_src = parts_dir[0].split()
				if len(parts_src)>=3:
					ts_info = parts_src[1].strip()
					src_info = parts_src[2].strip()
					dest_info = parts_dir[1].strip()
					ts=self.parse_time(ts_info)
					node = {"ts":ts, "src":src_info, "dst":dest_info}
					if self.is_pure_protocal(dest_info,"TCP"):
						node["ID"] = metrics.D_ID_NET_TCP
						node["ID_NOTE"] = metrics.D_ID_NET_TCP_NOTE
						node = self.combain_src_dest(node)
						ret.append(node)
		return ret

	def tcp_info(self):
		cmd = ['/usr/bin/tshark', '-n', '-ta', '-r'+ self.info["tcpdump_log_path"], 'tcp']
		output = self.check_output_safe(cmd)
		output_list = self.normalise(output.splitlines())
		data_list = self.handle_tcp(output_list)
		#self.log.info("tcp: %s",str(data_list))
		self.action_info.extend(data_list)

	def handle_https(self, output_list):
		ret=[]
		for line in output_list:
			parts_dir = line.split("->")
			if len(parts_dir) >=2:
				parts_src = parts_dir[0].split()
				if len(parts_src)>=3:
					ts_info = parts_src[1].strip()
					src_info = parts_src[2].strip()
					dest_info = parts_dir[1].strip()
					ts=self.parse_time(ts_info)
					node = {"ts":ts, "src":src_info, "dst":dest_info}
					if self.is_pure_protocal(dest_info,"TCP"):
						node["ID"] = metrics.D_ID_NET_HTTPS
						node["ID_NOTE"] = metrics.D_ID_NET_HTTPS_NOTE
						node = self.combain_src_dest(node)
						ret.append(node)
		return ret
		
	def https_info(self):
		cmd = ['/usr/bin/tshark', '-n', '-ta', '-r'+ self.info["tcpdump_log_path"], 'ssl']
		output = self.check_output_safe(cmd)
		output_list = self.normalise(output.splitlines())
		#self.log.info("https: %s",str(output_list))
		data_list = self.handle_https(output_list)
		self.action_info.extend(data_list)

	def getCommonName(self, output):
		ret=""
		parttern = 'id-at-commonName='
		st_pos = output.find(parttern)
		if -1 != st_pos:
			end_pos = output.find(',', st_pos+len(parttern))
			if -1 != end_pos:
				print("st:%d, ed:%d"%(st_pos,end_pos))
				ret = output[st_pos+len(parttern): end_pos]
			else:
				ret = output[st_pos+len(parttern)]
		return ret

	def handle_certificate(self, output):
		ret = []
		root = ET.fromstring(output)
		ts_list = root.findall(".//field[@name='timestamp']")
		if len(ts_list):
			ts_node = ts_list[0]
			ts_float = 0
			try:
				tmp = ts_node.get('value')
				ts_float = float(tmp)
			except Exception as e:
				self.log.error("get timestamp error: err: %s",str(e))
				ts_float = time.time()
			ts = datetime.datetime.fromtimestamp(ts_float)
			cert_list = root.findall(".//field[@name='ssl.handshake.certificate']")
			for node in cert_list:
				commonName = self.getCommonName(node.get('showname'))
				issuer_list = node.findall(".//field[@name='x509if.rdnSequence']")
				if len(issuer_list):
					issuer = issuer_list[0]
					issuerName = self.getCommonName(issuer.get('showname'))
					src_info = "certificate information"
					dest_info = "%s is issued by %s"%(commonName,issuerName)
					self.log.info(dest_info)
					node = {"ts":ts, "src":src_info, "dst":dest_info}
					node["ID"] = metrics.D_ID_NET_CERT
					node["ID_NOTE"] = metrics.D_ID_NET_CERT_NOTE
					ret.append(node)
		return ret

	def certificate_info(self):
		cmd = ['/usr/bin/tshark', '-n', '-ta', '-Tpdml', '-r'+ self.info["tcpdump_log_path"], 'ssl']
		(output,ret) = self.check_output_ret_safe(cmd)
		if 0 == ret:
			data_list = self.handle_certificate(output)
			self.log.info("certificate: %s",str(data_list))
			self.action_info.extend(data_list)
		else:
			self.log.info("There is no certificate_info. output: %s, ret: %d",output,ret)

	def handle_udp(self, output_list):
		ret=[]
		for line in output_list:
			parts_dir = line.split("->")
			if len(parts_dir) >=2:
				parts_src = parts_dir[0].split()
				if len(parts_src)>=3:
					ts_info = parts_src[1].strip()
					src_info = parts_src[2].strip()
					dest_info = parts_dir[1].strip()
					ts=self.parse_time(ts_info)
					node = {"ts":ts, "src":src_info, "dst":dest_info}
					#self.log.debug("node: %s",str(node))
					# DNS is also UDP
					if self.is_pure_protocal(dest_info,"UDP") or self.is_pure_protocal(dest_info,"DNS") :
						node["ID"] = metrics.D_ID_NET_UDP
						node["ID_NOTE"] = metrics.D_ID_NET_UDP_NOTE
						node = self.combain_src_dest(node)
						ret.append(node)
		return ret

	def udp_info(self):
		cmd = ['/usr/bin/tshark', '-n', '-ta', '-r'+ self.info["tcpdump_log_path"], 'udp']
		output = self.check_output_safe(cmd)
		output_list = self.normalise(output.splitlines())
		data_list = self.handle_udp(output_list)
		#self.log.info("udp_info: %s",str(data_list))
		self.action_info.extend(data_list)

	def parse_nat(self, nat_line):
		parts = nat_line.split()
		node = {}
		for item in parts:
			kv_parts = item.split("=")
			if len(kv_parts)>=2:
				k = kv_parts[0].strip()
				v = kv_parts[1].strip()
				node[k] = v
		return node

	def handle_kernel_log_net(self, output_list):
		nat_list = []
		for line in output_list:
			nat_pos = line.find("[NAT]")
			if -1!=nat_pos:
				nat_line = line[nat_pos+len("[NAT]"):]
				nat_node = self.parse_nat(nat_line)
				nat_list.append(nat_node)
		self.info['NAT_LIST'] = nat_list
		self.log.info("NAT_LIST: %d count",len(self.info['NAT_LIST']))

	def kernel_log_net_info(self):
		cmd = ['/bin/grep','NAT',self.cfg.kernel_log_path]
		output = self.check_output_safe(cmd)
		output_list = self.normalise(output.splitlines())
		#self.log.info("kernel NET_NAT:%s",str(output_list))
		self.handle_kernel_log_net(output_list)

	def pick_protocal(self, dest_info):
		protocal_list = ["TCP","UDP","HTTP","HTTPS","DNS"]
		for item in protocal_list:
			pos = dest_info.find(item)
			if -1!=pos:
				return item

	def parse_dest_protocal_info(self, dest_info):
		arrow_pos = dest_info.find("->")
		dest_ip = ""
		protocal_str = ""
		if -1!=arrow_pos:
			dest_info = dest_info[arrow_pos+len("->"):]
		dest_ip_re = re.compile(r'\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b')
		result = dest_ip_re.search(dest_info)
		if result:
			groups = result.groups()
			if len(groups):
				dest_ip = groups[0]
				protocal_str = self.pick_protocal(dest_info)
		return (dest_ip, protocal_str)

	def nat_ajust(self,src_ip,dest_ip,protocal_str):
		ajust_ip = ""
		tcp_list = ["HTTP","HTTPS"]
		udp_list = ["DNS"]
		for node in self.info["NAT_LIST"]:
			if node["SRC"] == src_ip:
				is_ok = False
				if node["PROTO"] == protocal_str:
					is_ok = True
				if node["PROTO"] == "TCP":
					if protocal_str in tcp_list:
						is_ok = True
				if node["PROTO"] == "UDP":
					if protocal_str in udp_list:
						is_ok = True
				if is_ok:
					#self.log.debug("ajust from %s to %s", dest_ip, node["DST"])
					# when ajust_ip has been found, break the loop
					ajust_ip =  node["DST"]
					break
		return ajust_ip

	def ajust_dest_ip(self):
		ajust_id_list = [metrics.D_ID_NET_DNS_QUERY, metrics.D_ID_NET_HTTP_SEND, metrics.D_ID_NET_TCP, metrics.D_ID_NET_HTTPS, metrics.D_ID_NET_UDP]
		for node in self.action_info:
			act_id = node["ID"]
			if act_id in ajust_id_list:
				src_ip = node["src"]
				if src_ip == self.cfg.net_eth0:
					(dest_ip, protocal_str) = self.parse_dest_protocal_info(node["dst"])
					#self.log.debug("dest_ip: %s, protocal_str: %s",dest_ip, protocal_str)
					ajust_ip = self.nat_ajust(src_ip,dest_ip,protocal_str)
					if len(ajust_ip):
						node["dst"] = node["dst"].replace(dest_ip,ajust_ip)
						#self.log.info("ajust_ip change %s to %s",dest_ip,ajust_ip)

	def network_info(self):
		self.socket_info()
		self.connect_info()
		self.dns_info()
		self.http_info()
		self.https_info()
		self.tcp_info()
		self.udp_info()
		self.certificate_info()
		if self.cfg.enable_inetsim:
			self.kernel_log_net_info()
			self.ajust_dest_ip()
		self.pick_ip_info()
		self.pick_dns_info()
		self.pick_url_info()

	def pick_url_info(self):
		target_ID = metrics.D_ID_NET_HTTP_SEND
		act_size = len(self.action_info)
		url_list=[]
		for i in range(act_size):
			node = self.action_info[i]
			if node["ID"] == target_ID:
				line = node['dst']
				parts = line.split()
				if len(parts)>=2:
					end_token = parts[-2]
					url_list.append(end_token)
		uniq_url_list = list(set(url_list))
		for url in uniq_url_list:
			act = ["pick_url", url, metrics.D_ID_NET_URL_INFO, metrics.D_ID_NET_URL_INFO_NOTE]
			self.add_action(act)

	def pick_dns_info(self):
		target_ID = metrics.D_ID_NET_DNS_QUERY
		act_size = len(self.action_info)
		dns_list=[]
		for i in range(act_size):
			node = self.action_info[i]
			if node["ID"] == target_ID:
				line = node['dst']
				parts = line.split()
				if len(parts)>=1:
					end_token = parts[-1]
					dns_list.append(end_token)
		uniq_dns_list = list(set(dns_list))
		for dns in uniq_dns_list:
			act = ["pick_dns",dns, metrics.D_ID_NET_DNS_INFO, metrics.D_ID_NET_DNS_INFO_NOTE]
			self.add_action(act)

	def pick_ip_info(self):
		lo_id = metrics.D_ID_NET_SOCEKT
		hi_id = metrics.D_ID_LIBC_accept
		#[lo_id, hi_id]
		act_size = len(self.action_info)
		ip_list=[]
		for i in range(act_size):
			node = self.action_info[i]
			if node["ID"] >=lo_id and node["ID"] <=hi_id:
				(is_succeed,ret) = self.pick_ip(node['src'])
				if is_succeed:
					ip_list.append(ret)
				parts = node['dst'].split("->")
				for p in parts:
					(is_succeed,ret) = self.pick_ip(p)
					if is_succeed:
						ip_list.append(ret)
		uniq_ip_list = list(set(ip_list))
		for ip in uniq_ip_list:
			if self.is_public_ip(ip):
				act=["pick_ip", ip, metrics.D_ID_NET_IP_INFO, metrics.D_ID_NET_IP_INFO_NOTE]
				self.add_action(act)

	def sort_and_add_action(self):
		sorted_list = sorted(self.action_info, key=lambda x:x['ts'])
		for node in sorted_list:
			if node.has_key('comment'):
				self.add_action([node['src'],node['dst'],node['ID'],node['ID_NOTE'],node['comment']])
			else:
				self.add_action([node['src'],node['dst'],node['ID'],node['ID_NOTE']])

	def output(self, fmt):
		self.log.info("The output will be generated with format %s", fmt)
		self.add_action(self.create_end_action()) # this will be the last action
		# output
		output_json = json.dumps(self.action_list, indent=4, sort_keys=False)
		output_fname = self.info["hash_md5"]+".dynamic"
		self.write_file(output_fname,output_json)
	def chmod_exe(self):
		file_path = self.cfg.target_abs_path
		os.chmod(file_path, stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO)
		self.log.info("change mode to 0777")

	def chose_loader(self):
		file_type = self.info["filetype"]
		if -1!=file_type.find("64"):
			return self.cfg.target_loader_64
		else:
			return self.cfg.target_loader_32

	def launch(self):
		self.prepare_monitor_before()
		file_path = self.cfg.target_abs_path
		self.chmod_exe()
		self.log.info("the program %s will be launched.",file_path)
		loader = self.chose_loader()
		#LD_DEBUG=bindings LD_DEBUG_OUTPUT=ld.log
		# deep copy is important
		#loader_env = copy.deepcopy(os.environ)
		loader_env = os.environ.copy()
		if "ltrace" == self.cfg.decided_trace_type:
			# LD_DEBUG for bindings, only dynamically linked elf supports
			loader_env["LD_DEBUG"]="bindings"
			loader_env["LD_DEBUG_OUTPUT"]=self.cfg.ld_debug_log_abs
			loader_env["LD_BIND_NOW"]="1"
			self.log.info("LD_DEBUG_OUTPUT : %s",loader_env["LD_DEBUG_OUTPUT"])
		# remove proxy setting if in inetsim mode
		if self.cfg.enable_inetsim:
			loader_env.pop("http_proxy",None)
			loader_env.pop("https_proxy",None)
		p=None
		try:
			p = subprocess.Popen([loader, file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=loader_env)
		except OSError as e:
			self.log.critical("popen error: %s",str(e))
			os._exit(3)
		if "ltrace" == self.cfg.decided_trace_type:
			# It must be removed, otherwise the following popen will use this env.
			loader_env.pop("LD_DEBUG",None)
			loader_env.pop("LD_DEBUG_OUTPUT",None)
			loader_env.pop("LD_BIND_NOW",None)
		# have to wait for a while
		# important
		time.sleep(1)
		#TODO not safe , will be blocked.
		#TODO try another way to obtain pid
		str_pid = p.stdout.readline()
		str_pid = str_pid.strip()
		target_pid=0
		try:
			target_pid = int(str_pid)
		except ValueError as e:
			self.log.error("get pid error")
		self.info["target_pid"]=target_pid
		self.info["target_name"] = os.path.basename(file_path)
		self.log.info("loader got pid: %s",str_pid)
		self.prepare_monitor_after()
		self.log.info("the process %s will be continue to execute",str_pid)
		# comment for debug
		# important
		time.sleep(1)
		p.send_signal(signal.SIGCONT)
		# TODO set timeout
		time_limit_dynamic = self.cfg.time_limit_dynamic
		time_tick =0
		is_terminated = False
		self.time_info["dyn_pre_launch_time"] = time.time()
		self.time_info["pre_launch_time_obj"] = datetime.datetime.utcnow()
		while time_tick < time_limit_dynamic:
			ret = p.poll()
			if ret is None:
				time.sleep(1)
				time_tick = time_tick+1
				self.log.info("wait for target termination %d seconds passed, limit:%d", time_tick,time_limit_dynamic)
			else:
				is_terminated = True
				self.log.info("target finished pid: %s, retcode: %d",str_pid,ret)
				if 0!=ret:
					(stdoutdata, stderrdata) = p.communicate()
					self.log.error("target exec stdout: %s", stdoutdata)
					self.log.error("target exec stderr: %s", stderrdata)
				break
		self.log.info("pid: %s, is_terminated: %r, time_tick: %d, time_limit_dynamic: %d",str_pid,is_terminated,time_tick,time_limit_dynamic)
		if is_terminated:
			# child process may continue to work.
			while time_tick < time_limit_dynamic:
				self.log.info("wait for child process, time_tick: %d, time_limit_dynamic: %d",time_tick,time_limit_dynamic)
				time.sleep(1)
				time_tick = time_tick+1
		else:
			self.log.info("target exec timeout %d seconds", time_tick)
			# I prefer kill -9 rather than SIGTERM
			p.kill()
			(stdoutdata,stderrdata) = p.communicate()
			retcode = p.returncode
			self.log.info("target was killed pid: %s, retcode: %d",str_pid,retcode)
		self.log.info("finally time_tick: %d, time_limit_dynamic: %d",time_tick,time_limit_dynamic)
		self.time_info["dyn_post_launch_time"] = time.time()
		# kill all, no mater is_terminated or not
		cmd = ["/usr/bin/pkill","-9",self.info["target_name"]]
		output = self.check_output_safe(cmd)
		self.log.info("pkill all %s",self.info["target_name"])
		loader_base = os.path.basename(loader)
		cmd = ["/usr/bin/pkill","-9",loader_base]
		output = self.check_output_safe(cmd)
		self.log.info("pkill all %s",loader_base)
		# important
		time.sleep(1)
		self.stop_monitor()

	def post_launch(self):
		if self.cfg.enable_mem_analysis:
			self.mem_analysis()
		is_deleted = self.check_self_delete()
		if not is_deleted:
			is_modified = self.check_self_modified()
			is_locked = self.check_file_locked()

	def mem_analysis(self):
		self.prepare_LiME()
		self.prepare_vol()
		self.mem_acquisition()
		self.parse_mem()

	def prepare_vol(self):
		cmd = ['/bin/bash', self.cfg.update_vol_profile_path]
		(output,ret) = self.check_output_ret_safe(cmd)
		self.log.info("vol profile update: %s",output)

	def prepare_LiME(self):
		self.log.info("LiME src path: %s", self.cfg.lime_src_path)
		cmd = ['/bin/uname', '-r']
		(output,ret) = self.check_output_ret_safe(cmd)
		if 0==ret:
			self.cfg.kernel_version = output.strip()
			self.log.info("kernel: %s", self.cfg.kernel_version)
			cmd = ['/usr/bin/make', '-C', self.cfg.lime_src_path]
			(output,ret) = self.check_output_ret_safe(cmd)
			if 0==ret:
				self.cfg.lime_ko_path =  os.path.join(self.cfg.lime_src_path,"lime-%s.ko"%(self.cfg.kernel_version))
				self.log.info("lime ko path: %s", self.cfg.lime_ko_path)
		else:
			self.log.error("uname error: %s",output)

	def mem_acquisition(self):
		if os.path.exists(self.cfg.lime_ko_path):
			cmd = ["/sbin/insmod",self.cfg.lime_ko_path,"path=%s format=lime"%(self.cfg.mem_dump_path)]
			(output, ret) = self.check_output_ret_safe(cmd)
			if 0==ret:
				self.log.info("mem dump: %s",self.cfg.mem_dump_path)
			else:
				self.log.error("mem dump error: %s", output)
		#rmmod
		cmd = ['/sbin/rmmod', 'lime']
		(output, ret) = self.check_output_ret_safe(cmd)
		self.log.info("rmmod lime, ret=%d",ret)

	def parse_mem(self):
		self.vol_bash()
		self.vol_pstree()

	def vol_pstree(self):
		cmd = ['/usr/bin/vol.py', '-f%s'%(self.cfg.mem_dump_path), '--profile=%s'%(self.cfg.vol_profile_name), 'linux_pstree']
		(output, ret) = self.check_output_ret_safe(cmd)
		self.log.info("vol_pstree:%s",output)
		is_ok = (-1==output.find("No suitable")) # No suitable can not be found
		if is_ok:
			pass
		else:
			self.log.info("mem dump error, please try again")

	def vol_bash(self):
		cmd = ['/usr/bin/vol.py', '-f%s'%(self.cfg.mem_dump_path), '--profile=%s'%(self.cfg.vol_profile_name), 'linux_bash']
		(output, ret) = self.check_output_ret_safe(cmd)
		self.log.info("vol_bash:%s",output)
		is_ok = (-1==output.find("No suitable")) # No suitable can not be found
		if is_ok:
			output_list = self.normalise(output.splitlines())
			self.parse_vol_bash(output_list)
		else:
			self.log.info("mem dump error, please try again")

	def parse_vol_bash(self, output_list):
		enable_parse = False
		pre_launch_time_obj = self.time_info["pre_launch_time_obj"]
		pre_launch_time_obj =pre_launch_time_obj.replace(1900,1,1)
		self.log.info("pre_launch_time_obj: %s",str(pre_launch_time_obj))
		for line in output_list:
			if enable_parse:
				parts = line.split()
				if len(parts) >=6:
					pid = parts[0]
					name = parts[1]
					cmd_time_str = parts[3]
					cmd_time_obj = datetime.datetime.strptime(cmd_time_str,"%H:%M:%S")
					cmd = " ".join(parts[5:])
					#self.log.info("vol_bash: %s %s",str(cmd_time_obj), cmd)
					if cmd_time_obj >= pre_launch_time_obj:
						self.log.info("[hit] vol_bash: %s",cmd)
			if line.startswith("----"):
				enable_parse=True

	def check_file_locked(self):
		file_path = self.cfg.target_abs_path
		cmd = ['/bin/fuser', '-v', file_path]
		(stdoutdata,stderrdata) = self.check_output_std(cmd)
		self.log.info("stdout:%s, stderr:%s"%(stdoutdata,stderrdata))
		output_list = self.normalise(stderrdata.splitlines())
		# remove 2 lines
		if len(output_list)>=2:
			self.parse_fuser(output_list[2:])
			return True
		else:
			return False

	def parse_fuser(self, output_list):
		for line in output_list:
			parts = line.split()
			if len(parts)>=3:
				user_name=parts[0]
				access_mode=parts[1]
				process_name=parts[2]
				act = [process_name, "process=%s, user=%s, access=%s"%(process_name, user_name,access_mode), metrics.D_ID_FILE_LOCK, metrics.D_ID_FILE_LOCK_NOTE]
				self.add_action(act)

	def check_self_modified(self):
		file_path = self.cfg.target_abs_path
		old_md5 = self.info["hash_md5"]
		if os.path.exists(file_path):
			new_md5 = base.BaseAnalyzer.get_md5_by_fname(file_path)
			self.log.debug("old_md5:%s, new_md5:%s"%(old_md5, new_md5) )
			if 0!=cmp(old_md5, new_md5):
				self.log.info("self modified detected")
				act = [file_path,"self modified detected, old_md5=%s, new_md5=%s"%(old_md5, new_md5), metrics.D_ID_SELF_MODIFIED, metrics.D_ID_SELF_MODIFIED_NOTE]
				self.add_action(act)
				return True
			else:
				return False
		else:
			self.log.error("file %s dose not exist"%(file_path))
			#delete is also a kind of modified
			return True

	def check_self_delete(self):
		file_path = self.cfg.target_abs_path
		if not os.path.exists(file_path):
			act = [file_path,"self delete detected, PATH=%s"%(file_path), metrics.D_ID_SELF_DELETE, metrics.D_ID_SELF_DELETE_NOTE]
			self.log.info("self delete detected")
			self.add_action(act)
			return True
		else:
			return False			

	def stop_monitor(self):
		self.log.info("stopping the monitor")
		if "ltrace" == self.cfg.decided_trace_type:
			self.stop_ltrace()
		else:
			self.stop_strace()
		self.stop_sysdig()
		if self.cfg.enable_inetsim:
			self.stop_network_nat()
			self.stop_inetsim()
		self.stop_tcpdump()

	def clean_kernel_log(self):
		base.BaseAnalyzer.touchFile(self.cfg.kernel_log_path)
		self.log.info("kernel log truncked.")

	def start_inetsim(self):
		"""
		--config=<filename>            Configuration file to use.
		--log-dir=<directory>          Directory logfiles are written to.
		--data-dir=<directory>         Directory containing service data.
		--report-dir=<directory>       Directory reports are written to.
		--bind-address=<IP address>    Default IP address to bind services to.
		"""
		if os.path.exists("/var/run/inetsim.pid"):
			os.remove("/var/run/inetsim.pid")
		cmd = ["/usr/bin/pkill","inetsim"]
		output = self.check_output_safe(cmd)
		self.log.info(output)
		cmd = ["/usr/bin/inetsim","--bind-address",self.cfg.net_eth1,"--config",self.cfg.inetsim_cfg_path,"--log-dir",self.cfg.inetsim_log_dir,"--data-dir",self.cfg.inetsim_data_dir,"--report-dir",self.cfg.inetsim_log_report_dir]
		self.p_inetsim = subprocess.Popen( cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.log.info("inetsim starts, pid: %d",self.p_inetsim.pid)

	def stop_inetsim(self):
		self.log.info("trying to stop inetsim, pid: %d",self.p_inetsim.pid)
		count_down = 5
		cnt = 5
		while cnt >0 :			
			self.p_inetsim.terminate()
			ret = self.p_inetsim.poll()
			if ret is None:
				cnt = cnt-1
				self.log.info("failed to kill inetsim, sleep 1 second")
				time.sleep(1)
			else:
				self.log.info("inetsim has been killed: [%d/%d]",cnt,count_down)
				break
		(stdoutdata, stderrdata) = self.p_inetsim.communicate()
		retcode = self.p_inetsim.returncode
		self.log.info("stop inetsim, ret: %d, stdout: %s, stderr: %s",retcode, stdoutdata, stderrdata)

	def start_network_nat(self):
		pass

	def stop_network_nat(self):
		"""
		iptables -t nat -F
		"""
		cmd = ["/sbin/iptables","-t","nat","-F"]
		output = self.check_output_safe(cmd)
		self.log.info("iptalbes fllushed.")

	def start_ltrace(self):
		"""
		-f trace children
		-o output to file
		-tt timestamps
		-S trace system calls
		"""
		target_pid = self.info["target_pid"]
		log_file = os.path.join(self.cfg.file_log_dir,self.info["hash_md5"]+".ltrace")
		self.info["ltrace_log_path"] = log_file
		cmd = ['/usr/bin/ltrace','-f','-tt', '-S', '-o'+log_file,"-p"+str(self.info["target_pid"])]
		self.p_ltrace = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.log.info("ltrace starts, logfile:%s",self.info["ltrace_log_path"])

	def prepare_monitor_before(self):
		"""
		monitor which dose not need pid
		"""
		self.prepare_sysctl()
		self.clean_kernel_log()
		self.start_tcpdump()
		if self.cfg.enable_inetsim:
			self.start_network_nat()
			self.start_inetsim()

	def prepare_sysctl(self):
		cmd = ['/sbin/sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1']
		self.check_output_safe(cmd)
		cmd = ['/sbin/sysctl', '-w', 'kernel.randomize_va_space=0']
		self.check_output_safe(cmd)
		cmd = ['/sbin/sysctl', '-w', 'kernel.yama.ptrace_scope=0']
		self.check_output_safe(cmd)

	def trace_type_decision(self):
		if "auto" == self.cfg.trace_type:
			MagicLiteral = self.info["file"]
			self.log.debug("MagicLiteral: %s",MagicLiteral)
			if -1!=MagicLiteral.find("statically"):
				self.cfg.decided_trace_type = "strace"
			elif -1!=MagicLiteral.find("dynamically"):
				self.cfg.decided_trace_type = "ltrace"
		else:
			self.cfg.decided_trace_type = self.cfg.trace_type
		self.log.info("decided_trace_type: %s",self.cfg.decided_trace_type)

	def prepare_monitor_after(self):
		target_pid = self.info["target_pid"]
		self.log.info("preparing strace, tcpdump and sysdig, target_pid:%d",target_pid)
		if target_pid>0:
			self.start_sysdig()
			if "ltrace" == self.cfg.decided_trace_type:
				self.start_ltrace()
			else:
				self.start_strace()
		else:
			self.log.error("target_pid is invalid: %d",target_pid);
	def start_tcpdump(self):
		"""
		-w  Write  the raw packets to file rather than parsing and printing them out.
		-c 	count
		"""
		log_file = os.path.join(self.cfg.file_log_dir,self.info["hash_md5"]+".pcap")
		self.info["tcpdump_log_path"] = log_file
		cmd = ["/usr/sbin/tcpdump", "-iany", "-w"+self.info["tcpdump_log_path"], "-c%d"%(self.cfg.tcpdump_limit)]
		self.p_tcpdump = subprocess.Popen( cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.log.info("tcpdump starts, logfile:%s",self.info["tcpdump_log_path"] )
	def stop_tcpdump(self):
		self.p_tcpdump.send_signal(signal.SIGINT)
		(stdoutdata, stderrdata) = self.p_tcpdump.communicate()
		retcode = self.p_tcpdump.returncode
		self.log.info("stop tcpdump, ret: %d",retcode)

	def start_sysdig(self):
		"""
		-w <writefile>
		-F, --fatfile       Enable fatfile mode , which will generate too large event
		-n <number> 		Stop capturing after n events
		"""
		target_pid = self.info["target_pid"]
		log_file = os.path.join(self.cfg.file_log_dir,self.info["hash_md5"]+".scap")
		self.info["sysdig_log_path"] = log_file
		cmd = ["/usr/bin/sysdig","-n%d"%(self.cfg.sysdig_limit),"-w"+self.info["sysdig_log_path"] ]
		self.p_sysdig = subprocess.Popen( cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.log.info("sysdig starts, logfile:%s",self.info["sysdig_log_path"] )

	def stop_sysdig(self):
		self.p_sysdig.send_signal(signal.SIGINT)
		(stdoutdata, stderrdata) = self.p_sysdig.communicate()
		retcode = self.p_sysdig.returncode
		self.log.info("stop sysdig, ret: %d, stdout: %s, stderr: %s",retcode, stdoutdata, stderrdata)

	def start_strace(self):
		"""
		-f -- follow forks
		-ff filename.pid
		-tt -- with usecs
		-xx -- print all strings in hex (not used)
		-y -- print paths associated with file descriptor arguments
		-o file -- send trace output to FILE instead of stderr
		-p pid
		"""
		target_pid = self.info["target_pid"]
		log_file = os.path.join(self.cfg.file_log_dir,self.info["hash_md5"]+".strace")
		self.info["strace_log_path"] = log_file
		self.p_strace = subprocess.Popen(["/usr/bin/strace", "-f", "-tt", "-y", "-o"+self.info["strace_log_path"], "-p"+str(self.info["target_pid"])], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		self.log.info("strace starts, logfile:%s",self.info["strace_log_path"])

	def stop_strace(self):
		# first check whether ternimated.
		retcode = self.p_strace.poll()
		if None == retcode:
			self.p_strace.send_signal(signal.SIGKILL)
			self.log.info("strace was forced to be exitsed")
			retcode=-1
		else:
			self.log.info("strace has already exited")
			(stdoutdata, stderrdata) = self.p_strace.communicate()
		
		self.log.info("stop strace, ret: %d",retcode)

	def stop_ltrace(self):
		# first check whether ternimated.
		retcode = self.p_ltrace.poll()
		if None == retcode:
			self.p_ltrace.send_signal(signal.SIGKILL)
			self.log.info("ltrace was forced to be exitsed")
		else:
			self.log.info("ltrace has already exited")
			(stdoutdata, stderrdata) = self.p_ltrace.communicate()
			self.log.info("stop ltrace, ret: %d",retcode)

	def add_action(self,action_node):
		self.action_cnt = self.action_cnt+1
		item = [self.action_cnt]+action_node
		self.action_list.append(item)

	def create_begin_action(self):
		className = self.__class__.__name__
		self.time_info["dyn_start_time"] = time.time()
		return [className, "ver:%s, ts:%s"%(self.cfg.version, self.local_date_time()), metrics.D_ID_START_DYN, metrics.D_ID_START_DYN_NOTE]

	def create_end_action(self):
		className = self.__class__.__name__
		self.time_info["dyn_end_time"] = time.time()
		# because time.time() is error in VM
		if self.info.get("error_msg",None):
			# exec error
			self.time_info["dyn_elapsed_time"] = self.time_info["dyn_end_time"] - self.time_info["dyn_start_time"]
		else:
			# exec succeed, so pre and post time is available
			self.time_info["dyn_elapsed_time"] = (self.time_info["dyn_end_time"]-self.time_info["dyn_post_launch_time"])+self.cfg.time_limit_dynamic+(self.time_info["dyn_pre_launch_time"]-self.time_info["dyn_start_time"])
		self.log.info("elapsed time: %f seconds",self.time_info["dyn_elapsed_time"])
		return [className, "%s, %s seconds used"%(self.local_date_time(),self.time_info["dyn_elapsed_time"]) , metrics.D_ID_STOP_DYN, metrics.D_ID_STOP_DYN_NOTE]

	def create_launch_action(self):
		file_path = self.cfg.target_abs_path
		return [file_path, self.local_date_time(), metrics.D_ID_LAUNCH, metrics.D_ID_LAUNCH_NOTE]

	def create_terminate_action(self):
		file_path = self.cfg.target_abs_path
		return [file_path, self.local_date_time(), metrics.D_ID_TERMINATE, metrics.D_ID_TERMINATE_NOTE]

	def create_noexe_action(self, error_msg):
		file_path = self.cfg.target_abs_path
		file_info = self.info["file"]
		return [file_path,"%s Unexecutable : %s, ErrorMsg: %s"%(file_path,file_info,error_msg), metrics.D_ID_ERROR_NOEXE, metrics.D_ID_ERROR_NOEXE_NOTE]
