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
Description: Linux Malware Analysis System, select executable ELF for Intel platform
Example:
Yes:
ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.18, from XXX, stripped
No:
ELF 32-bit LSB executable, MIPS, MIPS-I version 1 (SYSV), statically linked, stripped
ELF 32-bit LSB shared object, ARM, version 1 (SYSV), dynamically linked (uses shared libs), stripped
"""

import os
import sys
import subprocess

def is_exec_intel(file_path):
	ret = False
	if os.path.exists(file_path):
		cmd = ['/usr/bin/file', file_path]
		output=""
		try:
			output = subprocess.check_output(cmd)
		except subprocess.CalledProcessError as e:
			self.log.error("CalledProcessError: %s",str(e))
			output = e.output
		#debug
		#print output
		# filename: file_info
		sep = output.find(":")
		if -1!=sep:
			output = output[sep+1:]
			if len(output):
				output = output.strip()
				#Start with ELF
				if output.startswith("ELF"):
					pos = output.find("executable")
					# executable
					if -1 != pos:
						# x86-64 or Intel in the second part
						parts = output.split(',')
						if len(parts)>=2:
							platform = parts[1]
							platform = platform.strip()
							if platform.find("x86-64")!=-1 or platform.find("Intel")!=-1:
								ret=True
	#debug
	#print "result:%r"%(ret)
	return ret

def main(argc, argv):
	if 2 != argc:
		print "[usage] python %s [filepath] "%(argv[0])
		sys.exit(1)
	target_name = argv[1]
	result = is_exec_intel(target_name)
	if result:
		print "%s is executable for Intel platform"%(target_name)
	else:
		print "%s is not supported"%(target_name)

if "__main__" == __name__ :
	ret = main(len(sys.argv), sys.argv)
	sys.exit(ret)
