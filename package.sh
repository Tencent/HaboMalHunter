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
#Description: Linux Malware Analysis System : package

set -x

#create workspace
mkdir -p /tmp/EB93A6/
curr_dir=`pwd`
# compile
cd util/
cd target_loader
make clean
make 
make install
cd ..
cd ..

#unzip inetsim data
cd util/inetsim
unzip -o -qq inetsim.zip
cd ..
cd ..

# gen yara
cd util/yara
bash build.sh
cd ..
cd ..

# clean log
cd log/ && rm -rf * && cd ..
# clean tmp
rm -rf /tmp/AnalyzeControl_*

file_name=/tmp/AnalyzeControl_`/bin/date "+%m%d"`.zip
# clean first
rm -rf $file_name
7z a -r $file_name .
cp $file_name .

# pack test
cd test
bash build.sh
cd ..
7z a -r test_`/bin/date "+%m%d"`.zip test