# Tencent is pleased to support the open source community by making IoTHunter available.
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

class GetConnectIP():
    """plugin to get connect ip list"""

    def __init__(self):
        pass

    def analyze(self, behaviors):
        hit = 0
        self.ip_list = []
        for data in behaviors.socket_log['connect']:
            hit = 1
            addr = data['addr']
            if addr not in self.ip_list:
                self.ip_list.append(data['addr'])
        return hit

    def get_result(self):
        return self.ip_list

if __name__ == '__main__':
    pass
