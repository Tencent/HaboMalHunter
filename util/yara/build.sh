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
#Date:	Nov 22, 2016
#Description: Linux Malware Analysis System : yara rules builder

folder_list="malware"
IDX_NAME="index.yar"
rm -rf $IDX_NAME
for folder in $folder_list; do
	find $folder -regex ".*\.yara?" | awk '{print "include \"./" $0 "\""}' >> $IDX_NAME
done

cat $IDX_NAME
echo "index.yar has been generated."
# compile index.yar
python ./compile_yara.py index.yar
