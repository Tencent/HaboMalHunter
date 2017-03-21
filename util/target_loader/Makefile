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

all:
	gcc -g -O0 -m64 -o target_loader.64.elf main.c
	gcc -g -O0 -m32 -o target_loader.32.elf main.c
clean:
	rm -rf *.o target_loader.*.elf	
install:
	mkdir -p ../../bin
	cp ./target_loader.*.elf ../../bin/
