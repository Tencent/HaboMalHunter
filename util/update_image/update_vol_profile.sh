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
#Description: Linux Malware Analysis System : update vol

set -x

#build profile for volatility 
cd /usr/src/volatility-tools/linux
make
ls -la
cd -
VOL_PROFILE_DIR='/usr/share/vol_profile/'
rm -rf $VOL_PROFILE_DIR
mkdir -p $VOL_PROFILE_DIR
cp /usr/src/volatility-tools/linux/module.dwarf $VOL_PROFILE_DIR
cp /boot/System.map-`uname -r` $VOL_PROFILE_DIR
profile_file='/usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/Ubuntu1404.zip'
rm -rf $profile_file
zip /usr/lib/python2.7/dist-packages/volatility/plugins/overlays/linux/Ubuntu1404.zip $VOL_PROFILE_DIR/*
vol.py --info | grep Linux
echo "profile name: LinuxUbuntu1404x64"