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
Date:	August 08, 2016
Description: Linux Malware Analysis System
"""

"""
usage: AnalyzeControl.py [-h] [-v] [-t] [-z] [-i TIME_LIMIT_DYNAMIC] [-s] [-c]
                         [-e CONFIG_PATH] -l TARGET

Linux Malware Analysis System

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Display debug messages
  -t, --test            Only init and output Tag files
  -z, --zip             Indicate the target is a compressed package
  -i TIME_LIMIT_DYNAMIC, --time_limit_dynamic TIME_LIMIT_DYNAMIC
                        Set the timeout limitation (seconds) for dynamic
                        analysis
  -s, --static_only     Only static analysis
  -c, --clean           Clean the workspace
  -e CONFIG_PATH, --config_path CONFIG_PATH
                        Set the configuration path
  -l TARGET, --target TARGET
                        Set the absolute path of the target
"""

import sys
import os
import stat
import hashlib
import subprocess
import argparse
import ConfigParser
import logging
import logging.handlers
import shutil
import tempfile
import json

# Customised Package
import static
import dynamic
import metrics
import base

TIME_LIMIT_DYNAMIC_DEF=60 # 60 seconds for dynamic analysis timeout
BASE_HOME='/root/'
SECTION_DEF = 'main'
CONFIG_PATH_DEF='config.ini'
ENV_PREFIX='HABO_'
LOG_FMT = "%(asctime)s [%(filename)s:%(lineno)d %(funcName)s] %(levelname)s: %(message)s"

# global variables
log = logging.getLogger()

class Config_OBJ:
	def __init__(self, **entries):
		self.__dict__.update(entries)

def strTobool(value):
	true_list = ["yes", "y", "true", "t", "1"]
	false_list = ["no", "n", "false", "f", "0", "0.0", "", "none"]
	v = str(value).lower()
	if v in true_list:
		return True
	if v in false_list:
		return False
	return False

def init_cfg(cfg_path, args):
	"""
	The priority level: 
	define > args > env > ini
	"""
	cfg = {}
	# file
	conf_parser = ConfigParser.ConfigParser()
	if os.path.exists(cfg_path):
		conf_parser.read(cfg_path)
	for k,v in conf_parser.items(SECTION_DEF):
		cfg[k]=v

	# env
	for k,v in os.environ.items():
		if k.startswith(ENV_PREFIX):
			cfg_key = k[len(ENV_PREFIX):]
			cfg[cfg_key]=v
	
	# args
	args_dict =  vars(args)
	for k,v in args_dict.iteritems():
		cfg[k]=v

	# define
	cfg["BASE_HOME"] = BASE_HOME

	# adjustment
	file_log_dir = os.path.join(BASE_HOME, cfg["log_dir"])
	cfg["file_log_dir"] = file_log_dir
	cfg["static_finished_fname"] = os.path.join(file_log_dir,cfg["static_finished_fname"])
	cfg["dynamic_finished_fname"] = os.path.join(file_log_dir,cfg["dynamic_finished_fname"])

	# in order to using like cfg.log_dir
	cfg = Config_OBJ(**cfg)
	# force verbose
	cfg.verbose=True
	# convert string to int
	cfg.time_limit_dynamic = int(cfg.time_limit_dynamic)
	cfg.strings_limit = int(cfg.strings_limit)
	cfg.decompress_limit = int(cfg.decompress_limit)
	cfg.tcpdump_limit = int(cfg.tcpdump_limit)
	cfg.sysdig_limit = int(cfg.sysdig_limit)
	cfg.trace_limit = int(cfg.trace_limit)
	# convert string to bool
	cfg.is_inplace = strTobool(cfg.is_inplace)
	cfg.enable_inetsim = strTobool(cfg.enable_inetsim)
	cfg.enable_prefix_remove = strTobool(cfg.enable_prefix_remove)
	cfg.enable_mem_analysis = strTobool(cfg.enable_mem_analysis)
	return cfg

def init_arguments(argv):
	parser = argparse.ArgumentParser(description='Linux Malware Analysis System')
	parser.add_argument('-v', '--verbose', help='Display debug messages', action='store_true', required=False)
	parser.add_argument('-t', '--test', help='Only init and output Tag files', action='store_true', required=False)
	parser.add_argument('-z', '--zip', help='Indicate the target is a compressed package', action='store_true', required=False)
	#please config time out in ini file
	#parser.add_argument('-i', '--time_limit_dynamic', help='Set the timeout limitation (seconds) for dynamic analysis', type=int, default=TIME_LIMIT_DYNAMIC_DEF, required=False)
	parser.add_argument('-s', '--static_only', help='Only static analysis', action='store_true', required=False)
	parser.add_argument('-c', '--clean', help='Clean the workspace', action='store_true', required=False)
	parser.add_argument('-e', '--config_path', help='Set the configuration path', type=str, default=CONFIG_PATH_DEF, required=False)
	# required arg
	parser.add_argument('-l', '--target', help='Set the absolute path of the target', type=str, required=True)
	args = parser.parse_args()
	
	# cd into base_home
	os.chdir(BASE_HOME)
	# configuration init

	# I need change dir before pasering the configuration.
	cfg = init_cfg(args.config_path,args)
	return cfg

def init_log(cfg):
	# dir
	file_log_dir = cfg.file_log_dir
	if not os.path.exists(file_log_dir):
		os.mkdir(file_log_dir)

	fmt = logging.Formatter(LOG_FMT)

	# file
	file_log_path = os.path.join(BASE_HOME, cfg.log_dir, cfg.file_log)
	file_handler = logging.handlers.WatchedFileHandler(file_log_path)
	file_handler.setFormatter(fmt)
	log.addHandler(file_handler)

	# Console
	console_handler = logging.StreamHandler()
	console_handler.setFormatter(fmt)
	log.addHandler(console_handler)

	if cfg.verbose:
		log.setLevel(logging.DEBUG)
	else:
		log.setLevel(logging.ERROR)

	log.info("Linux Malware Analysis System. version:%s", cfg.version)
	log.debug("Configuration: ")
	log.debug(vars(cfg))
	# LD_DEBUG
	cfg.ld_debug_log_abs = os.path.join(file_log_dir, cfg.ld_debug_log)
	# inetsim dir
	if not os.path.exists(cfg.inetsim_log_dir):
		os.mkdir(cfg.inetsim_log_dir)
	if not os.path.exists(cfg.inetsim_log_report_dir):
		os.mkdir(cfg.inetsim_log_report_dir)

def init_workspace_inplace(cfg):
	workspace_dir = os.path.dirname(cfg.target)
	workspace_dir = os.path.abspath(workspace_dir)
	cfg.workspace_dir = workspace_dir
	if os.path.exists(cfg.target):
		target_abs_path = os.path.abspath(cfg.target)
		cfg.target_abs_path = target_abs_path
		os.chmod(target_abs_path, stat.S_IRUSR)
	else:
		log.critical("%s dose not exist.", cfg.target)
		os._exit(1)
	log.info("Target absolute path: %s", cfg.target_abs_path)

def init_workspace(cfg, is_inplace=False):
	log.info("init workspace is_inplace:%r",is_inplace)
	if is_inplace:
		init_workspace_inplace(cfg)
	else:
		# create a clean workspace
		workspace_dir = os.path.join(BASE_HOME,cfg.exec_home)
		if not os.path.exists(workspace_dir):
			os.mkdir(workspace_dir)
		else:
			shutil.rmtree(workspace_dir)
			os.mkdir(workspace_dir)
		cfg.workspace_dir = workspace_dir

		# copy target file into workspace
		if os.path.exists(cfg.target):
			shutil.copy(cfg.target, workspace_dir)
			target_abs_path = os.path.join(workspace_dir, os.path.basename(cfg.target))
			cfg.target_abs_path = target_abs_path
			os.chmod(target_abs_path, stat.S_IRUSR)
		else:
			log.critical("%s dose not exist.", cfg.target)
			os._exit(1)
		log.info("Target absolute path: %s", cfg.target_abs_path)
		# I can not change dir at here, the dir will be changed everytime when analyzer starts.

def get_filetype(file_path):
	if os.path.exists(file_path):
		output = subprocess.check_output(['/usr/bin/file', file_path])
		parts = output.split(":")
		file_type = "UNKNOWN"
		full_info = ""
		if len(parts) > 1:
			full_info = parts[1].strip()
			detailed_parts = parts[1].split()
			if len(detailed_parts) > 1:
				file_type = detailed_parts[0].strip()
		log.debug("file_type: %s, full_info: %s",file_type, full_info)
		return (file_type, full_info)
	else:
		log.critical("%s dose not exist.", file_path)
	return ("UNKNOWN","")

def is_compressed(file_path):
	(file_type, full_info) = get_filetype(file_path)
	compressed_type_list = ['7-zip', 'bzip2', 'gzip', 'XZ', 'Zip']
	ret = False
	if file_type in compressed_type_list:
		ret = True
	elif -1 != full_info.find("tar"):
		ret = True
	log.info("file %s compressed: %r",file_path,ret)
	return ret
def is_executable(file_path):
	(file_type, full_info) = get_filetype(file_path)
	# until now, ELF is only supported.
	exec_type_list = ['ELF']
	ret = False
	if file_type in exec_type_list:
		if -1 != full_info.find("executable"):
			ret = True
	log.info("file %s executable: %r",file_path, ret)
	return ret

def do_work(cfg, do_static, do_dynamic):
	# since dynamic analyzer needs info from static analyzer 
	if do_dynamic:
		do_static = True
		log.info("set do_static True, since dynamic analyzer needs info from static analyzer")

	if do_static:
		# static analysis
		log.info("will do_static analysis")
		static_analyzer = static.StaticAnalyzer(cfg)
		static_analyzer.start()
		static_analyzer.output('json')
		static_analyzer.end()
		if (cfg.target == cfg.main_target):
			cfg.main_target_md5 = static_analyzer.info["hash_md5"]
			log.info("main target md5: %s", cfg.main_target_md5)
		# dynamic analysis
		# check whether executable
	if do_dynamic:
		if is_executable(cfg.target):
			cfg.is_executable = True
		else:
			cfg.is_executable = False
			log.info("The target %s is not executable. do_dynamic: %r",cfg.target,do_dynamic)
		dynamic_analyzer = dynamic.DynamicAnalyzer(cfg)
		# dynamic analyzer will need info from static analyzer, such as md5
		dynamic_analyzer.info = static_analyzer.info
		dynamic_analyzer.start()
		dynamic_analyzer.output('json')
		dynamic_analyzer.end()
	else:
		log.info("skip dynamic analysis since do_dynamic is False")

def de_compress_top_lev(file_path):
	"""
	1. create dir with the format {file_path}_7zdump.
	2. only decompress the top level.
	"""
	bfs_list = [file_path]
	temp_list = []
	head = file_path
	if is_compressed(head):
		tmp_dir = head+"_7zdump"
		if not os.path.exists(tmp_dir):
			os.mkdir(tmp_dir)
		log.info("top_lev decompress dir: %s",tmp_dir)
		temp_list.append(tmp_dir)
		output = ""
		try:
			cmd_list = ["/usr/bin/7z","x","-y","-o"+tmp_dir,head]
			log.info("call 7z command: %s",str(cmd_list))
			output = subprocess.check_output(cmd_list)
		except subprocess.CalledProcessError as e:
			log.error("CalledProcessError: %s",str(e))
			output = e.output
		for root, dirs, files in os.walk(tmp_dir):
			for item in files:
				f = os.path.join(root,item)
				f = os.path.abspath(f)
				# make sure any file will be enqueue only once
				if (not f in bfs_list):
					#log.debug("en queue f: %s, queue:%s",f,str(queue))
					bfs_list.append(f)
	return (bfs_list, temp_list)			

def de_compress(file_path, is_inplace=False, decompress_limit=100):
	"""
	It will decompress the target as bfs order.
	"""
	queue = [file_path]
	bfs_list = []
	temp_list = []
	pop_cnt=0
	while len(queue):
		head = queue.pop(0)
		bfs_list.append(head)
		pop_cnt=pop_cnt+1
		if pop_cnt >= decompress_limit:
			log.info("pop_cnt:%d, limit:%d ,break",pop_cnt,decompress_limit)
			break
		if is_compressed(head):
			if is_inplace:
				tmp_dir = os.path.dirname(head)
				tmp_dir = os.path.abspath(tmp_dir)
			else:
				tmp_dir = tempfile.mkdtemp()
			log.info("is_inplace %r decompress dir: %s",is_inplace,tmp_dir)
			temp_list.append(tmp_dir)
			output = ""
			try:
				cmd_list = ["/usr/bin/7z","x","-y","-o"+tmp_dir,head]
				log.info("call 7z command: %s",str(cmd_list))
				output = subprocess.check_output(cmd_list)
			except subprocess.CalledProcessError as e:
				log.error("CalledProcessError: %s",str(e))
				output = e.output
			for root, dirs, files in os.walk(tmp_dir):
				for item in files:
					f = os.path.join(root,item)
					f = os.path.abspath(f)
					# make sure any file will be enqueue only once
					if (not os.path.samefile(head,f)) and (not f in queue) and (not f in bfs_list):
						#log.debug("en queue f: %s, queue:%s",f,str(queue))
						queue.append(f)

	return (bfs_list, temp_list)

def clean_temp(temp_list):
	for d in temp_list:
		log.info("clean dir: %s",d)
		shutil.rmtree(d, True)

def init_target_loader(cfg):
	file_path_32 = cfg.target_loader+".32.elf";
	file_path_64 = cfg.target_loader+".64.elf";
	if os.path.exists(file_path_32) and os.path.exists(file_path_64):
		log.info("target loader: %s, %s",file_path_32,file_path_64)
		# chmod 0777 targeT_loader
		os.chmod(file_path_64, stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO)
		os.chmod(file_path_32, stat.S_IRWXU|stat.S_IRWXG|stat.S_IRWXO)
		cfg.target_loader_64 = file_path_64
		cfg.target_loader_32 = file_path_32
	else:
		log.critical("failed to locate target loader: %s,%s",file_path_32,file_path_64)
		os._exit(2)

def generate_tag_file(cfg, do_static, do_dynamic):
	if do_static:
		base.BaseAnalyzer.touchFile(cfg.static_finished_fname)
		log.info("static tag file: %s is generated.", cfg.static_finished_fname)
	if do_dynamic:
		base.BaseAnalyzer.touchFile(cfg.dynamic_finished_fname)
		log.info("dynamic tag file: %s is generated.", cfg.dynamic_finished_fname)

def combine_static_perfile(cfg):
	main_log_path = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".static")
	log_dir = cfg.file_log_dir
	if os.path.exists(main_log_path):
		fi = open(main_log_path,"rb")
		main_info = json.load(fi)
		fi.close()
		main_info["SubBaseInfo"]=[]
		for item in cfg.bfs_list:
			if os.path.isfile(item):
				file_md5 = base.BaseAnalyzer.get_md5_by_fname(item)
				node = os.path.join(cfg.file_log_dir,file_md5+".static")
				log.info("combine %s, md5:%s, node:%s",item, file_md5, node)
				if os.path.exists(node) and node!=main_log_path:
					sub_f = open(node,"rb")
					sub_info = json.load(sub_f)
					sub_f.close()
					if len(sub_info["BaseInfo"])>0:
						node = sub_info["BaseInfo"][0]
						# fix Name info						
						if cfg.enable_prefix_remove:
							node["Name"] = base.BaseAnalyzer.prefix_remove(item)
						else:
							node["Name"] = item
						# fix "__full_path"
						node["__full_path"] = item
						node["ID"] = metrics.S_ID_SUB_BASE_INFO
						main_info["SubBaseInfo"].append(sub_info["BaseInfo"][0])
		fo = open(main_log_path,"wb")
		json.dump(main_info, fo, indent=4, sort_keys=False)
		fo.close()
		log.info("main static log updated %s",main_log_path)
	else:
		log.error("main log file: %s is missing",main_log_path)

def combine_static_log(cfg):
	main_log_path = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".static")
	log_dir = cfg.file_log_dir
	if os.path.exists(main_log_path):
		fi = open(main_log_path,"rb")
		main_info = json.load(fi)
		fi.close()
		main_info["SubBaseInfo"]=[]
		for root, dirs, files in os.walk(log_dir):
			for item in files:
				node = os.path.join(root,item)
				if node.endswith(".static") and node!=main_log_path:
					log.info("combine %s",node)
					sub_f = open(node,"rb")
					sub_info = json.load(sub_f)
					sub_f.close()
					if len(sub_info["BaseInfo"])>0:
						node = sub_info["BaseInfo"][0]
						node["ID"] = metrics.S_ID_SUB_BASE_INFO
						main_info["SubBaseInfo"].append(sub_info["BaseInfo"][0])
		fo = open(main_log_path,"wb")
		json.dump(main_info, fo, indent=4, sort_keys=False)
		fo.close()
		log.info("main static log updated %s",main_log_path)
	else:
		log.error("main log file: %s is missing",main_log_path)

def exratc_file_size(main_info, node_md5):
	sub_info_list = main_info["SubBaseInfo"]
	for item in sub_info_list:
		if item["MD5"] == node_md5:
			return item["SizeInfo"]
	return 0
def pick_largest_elf(cfg):
	"""
	Pick the largest in file size
	"""
	main_static = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".static")
	log_dir = cfg.file_log_dir
	if os.path.exists(main_static):
		fi = open(main_static,"rb")
		main_info = json.load(fi)
		fi.close()
	max_size = 0
	target_md5 = ""
	target_path = ""
	sub_info_list = main_info["SubBaseInfo"]
	for item in sub_info_list:
		full_path = item["__full_path"]
		if item["FileType"].startswith("ELF") and is_executable(full_path):
			node_md5 = item["MD5"]
			file_size = item["SizeInfo"]
			log.debug("file %s size: %d",node_md5, file_size)
			if max_size < file_size:
				max_size = file_size
				target_md5 = node_md5
				target_path = full_path
	if len(target_md5)>0:
		log.info("found ELF %s, md5 %s with file size: %d",target_path,target_md5,max_size)
	else:
		if len(sub_info_list)>0:
			item = sub_info_list[0]
			full_path = item["__full_path"]
			node_md5 = item["MD5"]
			file_size = item["SizeInfo"]

			max_size = file_size
			target_md5 = node_md5
			target_path = full_path
			log.info("Failed to find a ELF, pick first one: %s",target_path)
		else:
			log.info("Failed to pick any file.")
	return (target_md5,target_path)

def generate_main_dyn_log(cfg,target_md5):
	main_dynamic = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".dynamic")
	if len(target_md5)>0:
		src_file = os.path.join(cfg.file_log_dir, target_md5+".dynamic")
		if os.path.exists(src_file):
			log.info("found dynamic log: %s",src_file)
			dest_file = main_dynamic
			if src_file!=dest_file:
				shutil.copyfile(src_file, dest_file)
				log.info("copy file from %s to %s",src_file, dest_file)
			log.info("main dynamic log updated %s", main_dynamic)
		else:
			log.error("dynamic log %s can not be found.",src_file)
#discard
def pick_dynamic_log(cfg):
	"""
	Pick the largest in file size
	"""
	#main_dynamic = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".dynamic")
	main_static = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".static")
	log_dir = cfg.file_log_dir
	if os.path.exists(main_static):
		fi = open(main_static,"rb")
		main_info = json.load(fi)
		fi.close()
	max_size = 0
	target_md5 = ""
	for root, dirs, files in os.walk(log_dir):
		for item in files:
			node = os.path.join(root,item)
			if node.endswith(".static"):
				#log.debug("node name %s",os.path.basename(node))
				node_md5 = os.path.basename(node)[0:32]
				file_size = exratc_file_size(main_info,node_md5)
				log.debug("file %s size: %d",node_md5, file_size)
				if max_size < file_size:
					max_size = file_size
					target_md5 = node_md5

	if len(target_md5)>0:
		log.info("found dynamic log %s with file size: %d",target_md5,max_size)
		src_file = os.path.join(cfg.file_log_dir, target_md5+".dynamic")
		dest_file = main_dynamic
		# TODO why they are the same
		if src_file!=dest_file:
			shutil.copyfile(src_file, dest_file)
		log.info("main dynamic log updated %s", main_dynamic)

def generate_output_log(cfg, do_static, do_dynamic):
	"""
	generate output log as:
	output.static
	output.dynamic
	"""
	if do_static:
		main_static = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".static")
		output_static = os.path.join(cfg.file_log_dir, cfg.static_log)
		if os.path.exists(main_static):
			shutil.copyfile(main_static, output_static)
		log.info("output static logs %s have been generated", output_static)
	if do_dynamic:
		main_dynamic = os.path.join(cfg.file_log_dir,cfg.main_target_md5+".dynamic")
		output_dynamic = os.path.join(cfg.file_log_dir, cfg.dynamic_log)
		if os.path.exists(main_dynamic):
			shutil.copyfile(main_dynamic, output_dynamic)
		log.info("output dynamic logs %s have been generated", output_dynamic)

def compress_log(cfg):
	tmp_compressed_path = "/tmp/output.zip"
	if os.path.exists(tmp_compressed_path):
		os.remove(tmp_compressed_path)
	dest = os.path.join(cfg.file_log_dir,"output.zip")
	if os.path.exists(dest):
		os.remove(dest)
	f_name = shutil.make_archive("/tmp/output","zip",cfg.file_log_dir)
	shutil.move(f_name,dest)
	log.info("log files were packed into %s",cfg.file_log_dir)
	
def init_localtime():
	"""
	rm -f /etc/localtime
	ln -s -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	"""
	f_localtime = "/etc/localtime"
	f_src = "/usr/share/zoneinfo/Asia/Shanghai"
	if os.path.exists(f_localtime):
		os.remove(f_localtime)
	os.symlink(f_src,f_localtime)

def main(argc, argv):
	init_localtime()
	cfg = init_arguments(argv)
	init_log(cfg)
	log.info("version: %s",cfg.version)
	init_workspace(cfg,cfg.is_inplace)
	init_target_loader(cfg)
	cfg.bfs_list = []
	# whether is a compressed package
	# have to use cfg.target instead of target_abs_path, which is a internal variable.
	cfg.main_target = cfg.target
	if cfg.zip or is_compressed(cfg.target):
		log.info("compressed file %s , is_inplace: %r.",cfg.target, cfg.is_inplace)
		#(cfg.bfs_list, cfg.temp_list) = de_compress(cfg.target, cfg.is_inplace, cfg.decompress_limit)
		(cfg.bfs_list, cfg.temp_list) = de_compress_top_lev(cfg.target)
		for item in cfg.bfs_list:
			if os.path.isfile(item):
				cfg.target = item
				log.info("init workspace for item: %s",cfg.target)
				init_workspace(cfg,cfg.is_inplace)
				#only do_static
				do_work(cfg,True,False)
				log.info("analysis for item:%s finished",item)

		log.info("extract files list: %s",str(cfg.bfs_list))
		# combine static log
		#combine_static_log(cfg)
		combine_static_perfile(cfg)
		generate_output_log(cfg, True, False)
		# generate static tag file
		generate_tag_file(cfg,True, False)
		# At this time, the program outside VM will pick static log file
		# pick one dynamic log
		#pick_dynamic_log(cfg)
		(target_md5,target_path) = pick_largest_elf(cfg)
		if 0 != len(target_path):
			cfg.target = target_path
			log.info("init workspace for item: %s",cfg.target)
			init_workspace(cfg, cfg.is_inplace)
			#do both, dynamic needs static info
			do_work(cfg, True, True)
			generate_main_dyn_log(cfg, target_md5)
			generate_output_log(cfg, False, True)
		else:
			log.error("there is no elf to load for dynamic analysis. please check package.")
		# clean
		if not cfg.is_inplace:
			clean_temp(cfg.temp_list)
		# zip all log file
		compress_log(cfg)
		# generate dynamic tag file
		generate_tag_file(cfg,False, True)
	else:
		# do static first
		do_work(cfg, True, False)
		# no need to combain log since single mode
		generate_output_log(cfg, True, False)
		# generate static tag file
		generate_tag_file(cfg, True, False)

		# do both, dynamic needs static info
		do_work(cfg, True, True)
		generate_output_log(cfg, False, True)
		# zip all log file
		compress_log(cfg)
		# generate dynamic tag file
		generate_tag_file(cfg,False, True)
	return 0

if "__main__" == __name__ :
	ret = main(len(sys.argv), sys.argv)
	sys.exit(ret)