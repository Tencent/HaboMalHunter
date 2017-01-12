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
Description: Linux Malware Analysis System, static analyzer
"""
import logging
import time
import os
import datetime
import subprocess
import pwd
import re

class BaseAnalyzer():
	def __init__(self, cfg):
		self.log = logging.getLogger()
		self.cfg = cfg
		self.info = {}
		if cfg.verbose:
			self.log.setLevel(logging.DEBUG)
		else:
			self.log.setLevel(logging.ERROR)
		#chdir
		self.old_dir = os.getcwd()
		os.chdir(self.cfg.workspace_dir)
		self.log.info("The current working dir is %s", os.getcwd())

	def is_elf(self):
		file_info = self.info["file"]
		return (-1!=file_info.find("ELF"))

	def write_file(self, fname, ctx):
		file_path = os.path.join(self.cfg.file_log_dir, fname)
		f = open(file_path, "wb", 0)
		f.write(ctx)
		f.close()

	def normalise(self, input):
		output = None
		if isinstance(input, list):
			output = []
			for line in input:
				output.append(line.strip())
		elif isinstance(input, basestring):
			output = input.strip()
		return output

	@staticmethod
	def touchFile(fname):
		if not fname:
			return
		f = open(fname,"wb",0)
		f.close()

	@staticmethod
	def get_md5_by_fname(fname):
		output=""
		ret=0
		cmd=['/usr/bin/md5sum', '-b', fname]
		try:
			output = subprocess.check_output(cmd)
		except subprocess.CalledProcessError as e:
			output = e.output
			ret = e.returncode
		output = output.strip()
		if 0 == ret:
			return output[:32]
		else:
			return "0"*32

	@staticmethod
	def prefix_remove(fname):
		ret = fname
		prefix="/tmp/"
		start_off = len(prefix)
		if ret.startswith(prefix):
			ret = fname[start_off:]
			cut = ret.find("/")
			if -1!=cut:
				ret = ret[cut+1:]
		return ret

	def start(self):
		self.log.debug("Base starts")
		self.start_time = time.time()

	def end(self):
		self.log.debug("Base ends")
		self.end_time = time.time()
		self.elapsed_time = self.end_time - self.start_time
		# elapsed_time is error since time.time() error
		#self.log.info("elapsed time: %f seconds", self.elapsed_time)
		# chdir
		os.chdir(self.old_dir)
		self.log.info("The current working dir is %s", os.getcwd())

	def local_date_time(self):
		return time.strftime("%Y-%m-%d %H:%M:%S",time.localtime())
	def parse_time(self, str_ts):
		dot_pos = str_ts.find(".")
		substr = str_ts
		# python only support microseconds
		if -1!=dot_pos:
			substr = str_ts[0:dot_pos+6]
		#self.log.debug("parse_time: %s",substr)
		ts = datetime.datetime.strptime(substr,"%H:%M:%S.%f")
		return ts

	def check_output_safe(self,cmd):
		output=""
		self.log.info("call: %s",str(cmd))
		try:
			output = subprocess.check_output(cmd)
		except subprocess.CalledProcessError as e:
			self.log.error("CalledProcessError: %s",str(e))
			output = e.output
		return output

	def check_output_std(self,cmd):
		self.log.info("call: %s",str(cmd))
		stdoutdata=""
		stderrdata=""
		try:
			p = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			(stdoutdata,stderrdata) = p.communicate()
		except subprocess.CalledProcessError as e:
			self.log.error("CalledProcessError: %s",str(e))
			stderrdata = e.output
		return (stdoutdata,stderrdata)

	def check_output_ret_safe(self,cmd):
		output=""
		self.log.info("call: %s",str(cmd))
		ret=0
		try:
			output = subprocess.check_output(cmd)
		except subprocess.CalledProcessError as e:
			self.log.error("CalledProcessError: %s",str(e))
			output = e.output
			ret = e.returncode
		return (output,ret)

	def create_change_user(self, user_name):
		def ch_usr():
			u = pwd.getpwnam(user_name)
			self.log.info("current uid:%d, gid:%d",os.getuid(),os.getgid())
			os.setuid(u.pw_uid)
			os.setgid(u.pw_gid)
			self.log.info("after ch_usr, name:%s uid:%d, gid:%d",user_name,os.getuid(),os.getgid())
		return ch_usr

	def check_output_safe_by_user(self,cmd,user_name):
		output=""
		try:
			prefunc =  self.create_change_user(user_name)
			p = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=prefunc)
			(stdoutdata,stderrdata) = p.communicate()
			output = stdoutdata
		except subprocess.CalledProcessError as e:
			self.log.error("cmd: %s Error: %s",str(cmd),str(e))
			output = e.output
		#except OSError as e:
		#	self.log.error("cmd: %s Error: %s",str(cmd),str(e))
		return output

	def pick_ip(self, target_str):
		ip_port_re = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d*)?)')
		result = ip_port_re.search(target_str)
		is_succeed=False
		ret = None
		if result:
			groups = result.groups()
			if len(groups):
				is_succeed=True
				ret = groups[0]
		return (is_succeed,ret)

	def is_public_ip(self, target_ip):
		"""
		(^127\.)|
		(^10\.)|
		(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|
		(^192\.168\.)
		"""
		private_ip_re = re.compile(r'(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)')
		ret = private_ip_re.match(target_ip)
		if ret:
			self.log.info("target_ip:%s, ret:%s"%(target_ip,str(ret.group())))
		return None==ret