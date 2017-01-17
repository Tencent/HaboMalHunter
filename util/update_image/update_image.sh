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
#Description: Linux Malware Analysis System : update

set -x
#check root user
if [ "$(id -u)" != "0" ]; then
	echo "Please run as root"
fi

CFG_INSTALL_VBOX_TOOLS=0
if [ "$CFG_INSTALL_VBOX_TOOLS" != "0" ]; then
	#mount iso
	mount -t auto /dev/cdrom /mnt/cdrom/
	ls -la /mnt/cdrom/
	/mnt/cdrom/VBoxLinuxAdditions.run
fi

#seting ssh root login
#PermitRootLogin yes
sed -i 's/PermitRootLogin without-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
grep 'PermitRootLogin' /etc/ssh/sshd_config
service ssh restart
# set 1 to enable proxy
CFG_Enable_Proxy=0
PROXY_URL="__SET_YOUR_PROXY_HERE__"
if [ "$CFG_Enable_Proxy" -gt 0 ]; then
	echo "enable proxy with url: ${PROXY_URL}"
	#apt-get proxy
	echo "Acquire::http::Proxy \"${PROXY_URL}\";" > /etc/apt/apt.conf.d/01proxy
	#shell proxy
	cat > /etc/profile.d/proxy.sh << EOL
#!/bin/bash
export http_proxy='${PROXY_URL}'
export https_proxy='${PROXY_URL}'
EOL
	source /etc/profile.d/proxy.sh
fi

# apt-get install 
#install sysdig
curl -s https://s3.amazonaws.com/download.draios.com/DRAIOS-GPG-KEY.public | apt-key add -
curl -s -o /etc/apt/sources.list.d/draios.list http://download.draios.com/stable/deb/draios.list
apt-get update
apt-get install -y build-essential
apt-get install -y sysdig
apt-get install -y tshark 
apt-get install -y ssldump
apt-get install -y libcurl4-openssl-dev
apt-get install -y auditd
apt-get install -y php5-cli
apt-get install -y dwarfdump
apt-get install -y linux-tools-common
apt-get install -y linux-tools-`uname -r`
apt-get install -y linux-headers-generic
apt-get install -y p7zip-rar
apt-get install -y zip
apt-get install -y volatility-tools
apt-get -y autoremove
apt-get clean all

#modify /etc/wireshark/init.lua
sed -i 's/run_user_scripts_when_superuser = false/run_user_scripts_when_superuser = true/' /etc/wireshark/init.lua
sed -i '38irunning_superuser = false' /etc/wireshark/init.lua

# vol
bash ./update_vol_profile.sh
# build lime
download_url='https://github.com/504ensicsLabs/LiME/archive/v1.7.5.zip'
dest_path='/usr/share/LiME'
dest_file='LiME.zip'
unzip_dir='LiME-1.7.5'
mkdir -p $dest_path
cd $dest_path
curl -o$dest_file -L $download_url
unzip -o -qq $dest_file 
cd $unzip_dir/src 
make
ls -la *.ko
cp *.ko $dest_path/'lime.ko'
cd ..
cd -

# set timezone here
rm -f /etc/localtime
ln -s -f /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
date

# set root password
echo "Please change root password"
passwd
echo "Please poweroff"