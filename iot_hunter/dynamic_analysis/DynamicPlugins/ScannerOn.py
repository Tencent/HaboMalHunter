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

class ScannerOn():
    """Plugin to find scanneron cmd in network data."""

    def __init__(self):
        pass

    def analyze(self, behaviors):
        hit = 0
        for databyte in behaviors.recvfrom_data.values():
            print databyte
            if '!SCANNERON' in databyte:
                hit = 1
        return hit

    def get_result(self):
        return 'Scanner Command Find'

if __name__ == '__main__':
    pass
