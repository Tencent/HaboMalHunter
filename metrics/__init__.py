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
import static_action_id
import dynamic_action_id

# Accoring to the design plan, the type of static_action_id will be string and the type of dynamic_action_id will be integer.
def init():
	for key in dir(static_action_id):
		if key.startswith("S_ID_"):
			v = getattr(static_action_id,key)
			v = str(v)
			setattr(static_action_id,key,v)


	for key in dir(dynamic_action_id):
		if key.startswith("D_ID_") and not key.endswith("_NOTE"):
			v = getattr(dynamic_action_id,key)
			v = int(v)
			setattr(dynamic_action_id,key,v)

# call it
init()

# after formalising, it will be safe to export
from dynamic_action_id import *
from static_action_id import *
from syscall_table import syscall_table