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
import sys
import os
import subprocess
import json
import re
import traceback

import yara

# Custermised Package
sys.path.append("..")
import base
import metrics

log = logging.getLogger()

class StaticAnalyzer(base.BaseAnalyzer):
	def __init__(self, cfg):
		base.BaseAnalyzer.__init__(self,cfg)
		self.tag_file = cfg.static_finished_fname

	def start(self):
		try:
			self.log.info("StaticAnalyzer starts")
			base.BaseAnalyzer.start(self)
			# common
			# file
			self.file_info()
			# md5 sha1 ssdeep
			self.hash_info()
			# exiftool
			self.exiftool_info()
			# size
			self.size_info()
			# yara
			self.yara_info()

			if self.is_elf():
				# detect packer: upx
				packer = self.detect_packer()
				if None == packer:
					self.elf_str_dep_seg()
				else:
					self.log.info("packer %s detected", packer)
					is_ok = self.unpack()
					if is_ok:
						self.log.info("%s unpack is succeed",packer)
						# change target to unpacked file
						original_path = self.cfg.target_abs_path
						self.cfg.target_abs_path = self.cfg.target_unpacked_path
						self.elf_str_dep_seg()
						# change back
						self.cfg.target_abs_path = original_path
					else:
						self.log.error("unpack failed. packer : %s",packer)
		except Exception as e:
			self.log.error("static analysis error: %s"%(str(e)))
			self.log.error(traceback.format_exc())

	def detect_packer(self):
		# only support upx
		file_path = self.cfg.target_abs_path
		cmd = ["/usr/bin/upx","-q", "-t",file_path]
		output = self.check_output_safe(cmd)
		if -1!=output.find("[OK]"):
			return "upx"
		else:
			return None

	def unpack(self):
		file_path = self.cfg.target_abs_path
		target_unpacked_path = file_path+".upx"
		packer_name = "UPX"
		cmd = ["/usr/bin/upx", "-q", "-d", file_path, "-o%s"%(target_unpacked_path)]
		if os.path.exists(target_unpacked_path):
			os.remove(target_unpacked_path)
		(output,ret) = self.check_output_ret_safe(cmd)
		if 0 == ret:
			self.cfg.target_unpacked_path = target_unpacked_path
			packer_info={}
			packer_info["ID"] = metrics.S_ID_PACKER_INFO
			packer_info["packer_name"] = packer_name
			packer_info["hash_md5"] = base.BaseAnalyzer.get_md5_by_fname(target_unpacked_path)
			packer_info["file_size"] = os.path.getsize(target_unpacked_path)
			file_output = self.check_output_safe(['/usr/bin/file', target_unpacked_path])
			file_info = self.extract_file(self.normalise(file_output))
			packer_info["Magic_Literal"] = file_info
			self.info["packer_info"] = [packer_info]
			return True
		else:
			self.log.error("unpack error:%s",output)
			return False

	def elf_str_dep_seg(self):
		# string
		self.string_info()
		# ldd
		self.dependencies_info()
		# elf
		self.elf_info()

	def end(self):
		self.log.info("StaticAnalyzer ends")
		base.BaseAnalyzer.end(self)

# info
	def yara_info(self):
		"""
		{
			'tags': ['foo', 'bar'],
			'matches': True,
			'namespace': 'default',
			'rule': 'my_rule',
			'meta': {},
			'strings': [(81L, '$a', 'abc'), (141L, '$b', 'def')]
		}
		"""
		file_path = self.cfg.target_abs_path
		yara_info = []
		if os.path.exists(self.cfg.yara_rules_data):
			rules = yara.load(self.cfg.yara_rules_data)
			matches = rules.match(file_path)
			self.log.info(matches)
			if len(matches):
				for item in matches:
					self.log.info(type(item))
					node={}
					node["ID"] = metrics.S_ID_YARA_INFO
					node["str"] = item.rule
					yara_info.append(node)
		self.log.info(yara_info)
		self.info["yara_info"] = yara_info

	def size_info(self):
		file_path = self.cfg.target_abs_path
		if os.path.exists(file_path):
			self.info["size_info"] = os.path.getsize(file_path)
			self.log.info("file size_info: %d",self.info["size_info"])
		else:
			self.log.error("file: %s dose not exist",file_path)
	def get_machinetype(self):
		if self.info.has_key("machinetype"):
			return self.info["machinetype"]
		line = self.info["file"]
		parts = line.split(",")
		ret = "UNKNOWN"
		filetype = self.get_filetype()
		# only ELF need extract machine type
		if filetype.startswith("ELF"):
			if 1 < len(parts):
				ret = self.normalise(parts[1])
		self.info["machinetype"] = ret
		return ret
	def get_filetype(self):
		if self.info.has_key("filetype"):
			return self.info["filetype"]
		line = self.info["file"]
		st_ind = line.find(":")
		end_ind = line.find(",", st_ind+1)
		subline = self.normalise(line[st_ind+1:end_ind])
		self.log.debug("subline: %s",subline)
		parts = subline.split()
		ret = "UNKNOWN"
		if 1 == len(parts):
			ret = parts[0]
		elif 1< len(parts):
			if "ELF" == parts[0]:
				ret = parts[0]+parts[1][:2]
			else:
				ret = parts[0]
		# chane 7-zip to 7z
		if "7-zip" == ret:
			ret = "7z"
		self.info["filetype"] = ret
		return ret

	def file_info(self):
		file_path = self.cfg.target_abs_path
		if os.path.exists(file_path):
			output = self.check_output_safe(['/usr/bin/file', file_path])
			self.info["file"] = self.extract_file(self.normalise(output))
			self.log.info("file cmd: %s",output)
		else:
			self.log.error("file: %s dose not exist",file_path)
	def extract_file(self, line):
		parts = line.split(":")
		ret = ""
		if len(parts)>1:
			ret = parts[1].strip()
		return ret

	def hash_info(self):
		file_path = self.cfg.target_abs_path
		if os.path.exists(file_path):
			self.info["hash_md5"] = base.BaseAnalyzer.get_md5_by_fname(file_path)
			self.log.info("md5sum cmd: %s", self.info["hash_md5"])

			output = self.check_output_safe(['/usr/bin/sha1sum', '-b', file_path])
			self.info["hash_sha1"] = self.normalise(output)[:40]
			self.log.info("sha1sum cmd: %s", self.info["hash_sha1"])

			output = self.check_output_safe(['/usr/bin/sha256sum', '-b', file_path])
			self.info["hash_sha256"] = self.normalise(output)[:64]
			self.log.info("sha256sum cmd: %s", self.info["hash_sha256"])

			output = self.check_output_safe(['/usr/bin/ssdeep', file_path])
			self.info["hash_ssdeep"] = self.extract_ssdeep(output)
			self.log.info("ssdeep cmd: %s", self.info["hash_ssdeep"])
		else:
			self.log.error("file: %s dose not exist",file_path)
	def extract_ssdeep(self, line):
		parts = line.splitlines()
		if 1 < len(parts):
			subparts = parts[1].split(",")
			if 0 < len(subparts):
				return subparts[0]
		return ""

	def string_info(self):
		file_path = self.cfg.target_abs_path
		if os.path.exists(file_path):
			# ascii
			limit = "-n" + str(self.cfg.strings_limit)
			output = self.check_output_safe(['/usr/bin/strings', '-a', '-tx', limit, file_path])
			self.info['strings_ascii'] = self.normalise(output.splitlines())
			self.log.info("strings extracts %d ascii lines", len(self.info['strings_ascii']))
			# unicode16 16-bit littleendian
			output = self.check_output_safe(['/usr/bin/strings', '-a', '-tx', '-el', file_path])
			self.info['strings_utf16'] = self.normalise(output.splitlines())
			self.log.info("strings extracts %d utf16 lines", len(self.info['strings_utf16']))
		else:
			self.log.error("file: %s dose not exist",file_path)

	def dependencies_info(self):
		file_path = self.cfg.target_abs_path
		if os.path.exists(file_path):
			output = self.check_output_safe(['/usr/bin/ldd', file_path])
			self.info['dependencies'] = self.extract_dep(self.normalise(output.splitlines()))
			self.log.info("ldd cmd: %d so",len(self.info['dependencies']))
		else:
			self.log.error("file: %s dose not exist",file_path)

	def extract_dep(self, output_list):
		ret = []
		for line in output_list:
			parts = line.split("=>")
			if len(parts) > 0:
				node = {}
				node["SO_NAME"] = self.pick_path(parts[0].strip())
				node["ID"] = metrics.S_ID_SO_LIST
				node["SO_PATH"] = ""
				if len(parts) >1:
					node["SO_PATH"] = self.pick_path(parts[1])
				if 0!=len(node["SO_NAME"]):
					ret.append(node)
		return ret
	def pick_path(self, line):
		cut_pos = line.find("(0x")
		ret = ""
		if -1 != cut_pos:
			ret = line[0:cut_pos].strip()
		else:
			ret = line
		return ret

	def extract_elf_header(self, output_list):
		ret = {}
		for line in output_list:
			parts = line.split(":")
			if len(parts)>1:
				key=parts[0].strip()
				val=parts[1].strip()
				ret[key]=val
		return ret

	def elf_info(self):
		file_path = self.cfg.target_abs_path
		if os.path.exists(file_path):
			output = self.check_output_safe(['/usr/bin/readelf', '-h', file_path])
			self.info['elf_header'] = self.extract_elf_header(self.normalise(output.splitlines()))
			self.log.info("%d elf header",len(self.info['elf_header']))
			#self.log.debug(self.info['elf_header'])
			self.entry_point_info()
			# elf sections
			output = self.check_output_safe(['/usr/bin/readelf', '-S', file_path])
			self.info['elf_sections'] = self.extract_sections(self.normalise(output.splitlines()))
			self.log.info("%d elf sections", len(self.info['elf_sections']))
			# elf segments
			output = self.check_output_safe(['/usr/bin/readelf', '-l', file_path])
			self.info['elf_segments'] = self.extract_segments(self.normalise(output.splitlines()))
			# elf symbol
			output = self.check_output_safe(['/usr/bin/readelf', '-s', file_path])
			self.info['elf_dynsym'] = self.extract_dynsym(self.normalise(output.splitlines()))

		else:
			self.log.error("file: %s dose not exist",file_path)		

	def exiftool_info(self):
		file_path = self.cfg.target_abs_path
		if os.path.exists(file_path):
			output=self.check_output_safe(['/usr/bin/exiftool', file_path])
			self.info['exiftool_info'] = self.extract_exif(self.normalise(output.splitlines()))
		else:
			self.log.error("file: %s dose not exist",file_path)	
	def extract_exif(self, output_list):
		ret = {}
		for line in output_list:
			parts = line.split(":")
			if len(parts)>1:
				key=parts[0].strip()
				val=parts[1].strip()
				ret[key]=val
		return ret
	def extract_dynsym(self, output_list):
		data_processing = False
		imported_list = []
		exported_list = []
		ret = {}
		for line in output_list:
			if False == data_processing and line.startswith("Num"):
				data_processing=True
				continue
			if data_processing:
				#self.log.debug("line: %s",line)
				parts = line.split()
				if len(parts)>7:
					entry_type = parts[3]
					entry_ndx = parts[6]
					entry_name = self.extract_func_name(parts[7])
					item = "%s (%s)"%(entry_name,entry_type)
					if "UND" == entry_ndx.upper(): # imported
						imported_list.append(item)
					else: # exported
						exported_list.append(item)
		ret["imported_list"] = imported_list
		ret["exported_list"] = exported_list
		return ret

	def extract_func_name(self, full_name):
		at_pos = full_name.find("@")
		short_name = ""
		if -1!=at_pos:
			short_name = full_name[0:at_pos]
		else:
			short_name = full_name
		return short_name

	def entry_point_info(self):
		elf_header = self.info['elf_header']
		for k,v in elf_header.items():
			if k.startswith("Entry"):
				self.info['elf_entry_point'] = v
				self.log.info("elf_entry_point: %s",self.info['elf_entry_point'])
				break

	def extract_segments(self, output_list):
		segments_list = []
		st_ind = 0
		end_ind = 0
		ret = {}
		ret["interpreter"] = ""
		ret["segments_list"] = []
		ret["segments_secions_mapping"] = []
		for ind in range(len(output_list)):
			line = output_list[ind]
			if line.startswith("Program"):
				st_ind = ind+1
			if line.startswith("Section"):
				end_ind = ind-1
				break
		for ind in range(st_ind+2,end_ind,1):
			line = output_list[ind]
			if line.startswith("0x"):
				pass
			else:
				if -1 != line.find("interpreter"):
					st_interp = line.find(":")
					if -1 != st_interp:
						interp = line[st_interp+1:].strip(']')
						ret["interpreter"] = interp
				else:
					parts = line.split()
					if len(parts)>1:
						seg_name = parts[0]
						segments_list.append(seg_name)
		ret["segments_list"] = segments_list
		#mapping
		map_list = []
		st_ind = 0
		end_ind = 0
		for ind in range(len(output_list)):
			line = output_list[ind]
			if line.startswith("Segment"):
				st_ind = ind+1
		end_ind = len(output_list)
		cnt=0
		for ind in range(st_ind,end_ind):
			# check out of index
			if cnt >= len(segments_list) :
				break
			line = output_list[ind]
			parts = line.split()
			map_node = {}
			map_node["segments_index"]=str(cnt)
			map_node["segments_name"]=segments_list[cnt]
			map_node["segments_sections_list"] = []
			if len(parts)>1:
				map_node["segments_sections_list"] = parts[1:]
			ret["segments_secions_mapping"].append(map_node)
			cnt=cnt+1
		return ret

	def extract_sections(self, output_list):
		st_ind = 0
		end_ind = 0
		ret=[]
		# [st_ind, end_ind)
		for ind in range(len(output_list)):
			line = output_list[ind]
			if line.startswith('Section'):
				st_ind = ind+1
			if line.startswith('Key'):
				end_ind = ind
				break

		if end_ind>st_ind and len(output_list)>st_ind+1:
			offset = {}
			# calc offset
			for k in ['Name', 'Type', 'Address', 'Offset']:
				(st_offset,end_offset) = self.calc_offset(k,output_list[st_ind])
				offset[k] = [st_offset,end_offset]
				#self.log.debug("calc_offset %s[%d,%d)",k,st_offset,end_offset)

			for k in ['Size', 'EntSize', 'Flags', 'Link', 'Info', 'Align']:
				(st_offset,end_offset) = self.calc_offset(k,output_list[st_ind+1])
				offset[k] = [st_offset,end_offset]
				#self.log.debug("calc_offset %s[%d,%d)",k,st_offset,end_offset)
			# extract info
			re_exp = re.compile(r'\[\s*(\d+)\s*\]')
			for ind in range(st_ind+2,end_ind,1):
				if ind < len(output_list):
					line_up = output_list[ind]
					line_down = output_list[ind+1]
					#self.log.debug("ind: %d, line_up:%s, line_down: %s", ind, line_up, line_down)
					node = {}
					# id
					res = re_exp.search(line_up)
					if res:
						groups = res.groups()
						if len(groups)>=1:
							node['Index'] = groups[0]
						for k in ['Name', 'Type', 'Address', 'Offset']:
							node[k] = self.extract_info_by_offset(line_up,offset[k], True)
						for k in ['Size']:
							node[k] = self.extract_info_by_offset(line_down,offset[k], True)
						for k in ['Flags']:
							node[k] = self.extract_info_by_offset(line_down,offset[k], False)
						#self.log.debug("node: %s",str(node))
						ret.append(node)
		else:
			self.log.error('extract elf sections failed: %s',str(output_list))
		ret = self.sections_hash(ret)
		return ret

	def sections_hash(self, section_list):
		"""
		objcopy -O binary --only-section=.text ./ls tmp.bin
		"""
		#self.log.debug("section list: %s"%(str(section_list)))
		file_path = self.cfg.target_abs_path
		sections_file_list = []
		for sec in section_list:
			name = sec['Name']
			outfile = "%s.sec"%(name)
			cmd = ['/usr/bin/objcopy', '-Obinary', '--only-section=%s'%(name), file_path, outfile ]
			(output,ret) = self.check_output_ret_safe(cmd)
			if 0==ret and os.path.getsize(outfile):
				sec['hash_md5'] = base.BaseAnalyzer.get_md5_by_fname(outfile)
				output = self.check_output_safe(['/usr/bin/ssdeep', outfile])
				sec["hash_ssdeep"] = self.extract_ssdeep(output)
				sections_file_list.append(outfile)
			else:
				self.log.error("section %s hash error: %s"%(name,output))
		# generate mdb
		if 0!=len(sections_file_list):
			cmd = ['/usr/bin/sigtool','--mdb']
			cmd.extend(sections_file_list)
			#self.log.info("sigtool: %s",str(cmd))
			(output,ret) = self.check_output_ret_safe(cmd)
			if 0==ret:
				mdb_file_path = self.info["hash_md5"]+".mdb"
				self.write_file(mdb_file_path,output)
				self.info["mdb_info"] = self.generate_mdb(self.normalise(output.splitlines()))
			#remove section files, keep file for debug
			#for f in sections_file_list:
			#	os.remove(f)
		return section_list

	def generate_mdb(self, output_list):
		ret=[]
		for line in output_list:
			sec={"str":line, "ID": metrics.S_ID_MDB_INFO}
			ret.append(sec)
		return ret

	def extract_info_by_offset(self, line, offset_list, end_ignored):
		ret = ""
		if 2 == len(offset_list):
			st_ind = offset_list[0]
			if len(line) > st_ind:
				end_pos = len(line)
				if False == end_ignored:
					end_pos = offset_list[1]
				# find first char which is not space.
				old_st_ind = st_ind
				while st_ind < len(line) and ' ' == line[st_ind] :
					st_ind = st_ind+1
				subline = ""
				# check whether the value is none
				if st_ind - old_st_ind > 5 :
					pass
				else:
					cut_ind = line.find(' ',st_ind,end_pos)
					
					if -1 == cut_ind:
						subline = line[st_ind:]
					else:
						subline = line[st_ind:cut_ind]
				#self.log.debug("line: %s, subline: %s", line, subline)
				return subline
			else:
				self.log.error("st_ind %d is out of bound.",st_ind)
		else:
			self.log.error("offset memebers error")
		return ret

	def calc_offset(self,k,line):
		st_ind = line.find(k)
		end_ind = -1
		if -1 != st_ind:
			end_ind = st_ind+len(k)
		else:
			self.log.error("key: %s dose not exists in line: %s",k,line)
		return (st_ind, end_ind)

# output
	def output(self, fmt):
		self.log.info("output will be generated in format: %s", fmt)
		if "json" == fmt.lower():
			self.output_json()
		else:
			self.log.error("The output format %s has not been supported",fmt)
	def output_json(self):
		self.output_json_filetype()
		self.output_json_static()
		self.output_json_strings()

	def output_json_filetype(self):
		filetype = self.get_filetype()
		self.log.info("filetype: %s",filetype)
		filetype_json = json.dumps({"filetype":filetype})
		output_fname = self.info["hash_md5"]+".filetype"
		self.write_file(output_fname,filetype_json)

	def output_json_static(self):
		output = {}
		#BaseInfo
		output["BaseInfo"] = []
		base_info = {}
		base_info["FileType"] = self.get_filetype()
		base_info["ID"] = metrics.S_ID_BASE_INFO
		base_info["MD5"] = self.info["hash_md5"]
		base_info["SHA1"] = self.info["hash_sha1"]
		base_info["SHA256"] = self.info["hash_sha256"]
		base_info["SSDEEP"] = self.info["hash_ssdeep"]
		base_info["MachineType"] = self.get_machinetype()
		#base_info["Name"] = self.cfg.target_abs_path
		if self.cfg.enable_prefix_remove:
			base_info["Name"] = base.BaseAnalyzer.prefix_remove(self.cfg.target)
		else:
			base_info["Name"] = self.cfg.target
		# used for inner
		base_info["__full_path"] = self.cfg.target
		base_info["SizeInfo"] = self.info["size_info"]
		output["BaseInfo"].append(base_info)

		#Magic_Literal
		output["FileInfo"] = []
		magic_info = {}
		magic_info["MagicLiteral"] = self.info["file"]
		magic_info["ID"] = metrics.S_ID_MAGIC_LITERAL
		output["FileInfo"].append(magic_info)
		#Entry
		output["Entry"] = []
		entry_info = {}
		if self.get_filetype().startswith("ELF"):
			entry_info["Entry"] = self.info["elf_entry_point"][2:] # remove 0x
			entry_info["ID"] = metrics.S_ID_ENTRY_INFO
			output["Entry"].append(entry_info)

		#Icon
		#output["Icon"] = []

		#Size of file
		output["FileSize"] = []
		size_info = {}
		size_info["SizeInfo"] = self.info["size_info"]
		size_info["ID"] = metrics.S_ID_FILE_SIZE
		output["FileSize"].append(size_info)

		#output["Import"] = [] 
		import_info = {}
		if self.get_filetype().startswith("ELF"):
			import_info["Import_list"] = self.info['elf_dynsym']['imported_list']
			import_info["ID"] = metrics.S_ID_Import_LIST
		#TODO fix format
		#output["Import"].append(import_info)

		#Resource
		#output["Resource"] = []

		#Version
		#output["Version"] = []

		#dependencies
		output["Dependencies"] = []
		if self.get_filetype().startswith("ELF"):
			output["Dependencies"] = self.info.get("dependencies",[])
		# ELF header
		#output["ELF"] = []
		elf_info = {}
		if self.get_filetype().startswith("ELF"):
			# ELF header
			elf_header = {}
			elf_header["ELF_HEADER"] = self.info['elf_header']
			elf_header["ID"] = metrics.S_ID_ELF_HEADER
			elf_info["HEADER"] = elf_header
			# ELF sections
			elf_sections = {}
			elf_sections["ELF_SECTIONS"] = self.info['elf_sections']
			elf_sections["ID"] = metrics.S_ID_ELF_SECTIONS
			elf_info["SECTIONS"] = elf_sections
 			# ELF segments
 			elf_segments = {}
 			elf_segments["ELF_SEGMENTS"] = self.info['elf_segments']
 			elf_segments['ID'] = metrics.S_ID_ELF_SEGMENTS
 			elf_info["SEGMENTS"] = elf_segments
 			# ELF DYNSYM
 			elf_dynsym = {}
 			elf_dynsym["ELF_DYNSYM"] = self.info['elf_dynsym']
 			elf_dynsym['ID'] = metrics.S_ID_ELF_DYNSYM
 			elf_info["DYNSYM"] = elf_dynsym
 		#TODO fix the format
		#output["ELF"].append(elf_info)
		if self.get_filetype().startswith("ELF"):
			output["ELF_SECTIONS"] = self.output_elf_sections()
			output["ELF_SEGMENTS_MAP"] = self.output_elf_segments_mapping()
			output["ELF_HEADER"] = self.output_elf_header()
			output["STRINGS_ASCII"] = self.output_strings_ascii()
			output["IP_INFO"] = self.output_ip_info()
			output["SRC_FILE"] = self.output_source_info()
			if self.info.has_key("packer_info"):
				output["PACKER_INFO"] = self.info["packer_info"]
			if self.info.has_key("mdb_info"):
				output["MDB_INFO"] = self.info["mdb_info"]
		# exiftool
		output["ExifTool"] = []
		exif_info = self.info['exiftool_info']
		exif_info["ID"] = metrics.S_ID_EXIFTOOL
		output["ExifTool"].append(exif_info)
		# yara
		if len(self.info["yara_info"]):
			output["YARA"] = self.info["yara_info"]
		# output
		output_json = json.dumps(output, indent=4, sort_keys=False)
		output_fname = self.info["hash_md5"]+".static"
		self.write_file(output_fname,output_json)

	def output_ip_info(self):
		ret=[]
		for line in self.info["strings_ascii"]:
			parts = line.split()
			if len(parts)>=2:
				target_str = parts[1]
				(is_succeed, ip_info) = self.pick_ip(target_str)
				if is_succeed:
					node = {'offset':parts[0], 'str':ip_info, 'ID':metrics.S_ID_IP_INFO}
					ret.append(node)
		return ret
	def output_source_info(self):
		ret=[]
		source_re = re.compile(r'\.c$|\.cc$|\.cpp$|\.s$|\.asm$')
		for line in self.info["strings_ascii"]:
			parts = line.split()
			if len(parts)>=2:
				target_str = parts[1]
				result = source_re.search(target_str)
				if result:
					node = {'offset':parts[0], 'str':target_str, 'ID':metrics.S_ID_SRC_FILE_INFO}
					ret.append(node)
		return ret

	def output_strings_ascii(self):
		ret=[]
		for line in self.info["strings_ascii"]:
			parts = line.split()
			if len(parts)>=2:
				node = {'offset':parts[0], 'str':parts[1], 'ID':metrics.S_ID_STRING_ASCII}
				ret.append(node)
		return ret

	def output_elf_header(self):
		output = []
		header = self.info['elf_header']
		header["ID"] = metrics.S_ID_ELF_HEADER
		output.append(header)
		return output
		
	def output_elf_segments_mapping(self):
		mapping = self.info['elf_segments']['segments_secions_mapping']
		for node in mapping:
			node['ID'] = metrics.S_ID_ELF_SEGMENTS_MAP
		return mapping
	def output_elf_sections(self):
		for node in self.info['elf_sections']:
			node["ID"] = metrics.S_ID_ELF_SECTIONS
		return self.info['elf_sections']

	def output_json_strings(self):
		output = {}
		if self.get_filetype().startswith("ELF"):
			output["ASCII"] = []
			strings_ascii = {}
			strings_ascii["LIST"] = self.info["strings_ascii"]
			strings_ascii["ID"] = metrics.S_ID_STRING_ASCII
			output["ASCII"].append(strings_ascii)

			output["UTF16"] = []
			strings_utf16 = {}
			strings_utf16["LIST"] = self.info["strings_utf16"]
			strings_utf16["ID"] = metrics.S_ID_STRING_UTF16
			output["UTF16"].append(strings_utf16)
		else:
			pass
		output_json = json.dumps(output, indent=4, sort_keys=False)
		output_fname = self.info["hash_md5"]+".strings"
		self.write_file(output_fname,output_json)
