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
Date:	Nov 08, 2016
Description: Linux Malware Analysis System: compile yara
"""
import sys

import yara

def usage(argc, argv):
	print "python %s [index.yara]"%(argv[0])

def main(argc, argv):
	if 2!=argc:
		usage(argc, argv)
		return -1
	ifile = argv[1]
	ofile = "yara.bin"
	rules = yara.compile(ifile)
	rules.save(ofile)
	print "%s has been generated."%(ofile)
	return 0
if "__main__" == __name__ :
	ret = main(len(sys.argv), sys.argv)
	sys.exit(ret)