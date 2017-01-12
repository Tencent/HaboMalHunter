#!/bin/bash

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
#Date:	August 18, 2016
#Description: Linux Malware Analysis System : build test elf files

set -x
#clean
rm -rf bin
rm -rf *.zip
mkdir -p bin



BIN_32_LIST="fork.c dns.c read.c write.c self_delete.c libc_file.c"
BIN_64_LIST="${BIN_32_LIST} http.c https.c"

for source in $BIN_32_LIST; do
	base=$(basename $source .c)
	mod=32
	cmd="gcc -m$mod -o bin/${base}.$mod.elf $source"
	$cmd
done

for source in $BIN_64_LIST; do
	base=$(basename $source .c)
	mod=64
	LD_FLAGS="-lcurl"
	cmd="gcc -m$mod -o bin/${base}.$mod.elf $source $LD_FLAGS"
	$cmd
done

#pack 32
7z a -r test.32.zip bin/*.32.elf
#pack 64
7z a -r test.64.zip bin/*.64.elf
#pack all
7z a -r test.all.zip bin/
#pack multi
7z a -r test.mult.zip bin/
7z a test.mult.zip *
#end
