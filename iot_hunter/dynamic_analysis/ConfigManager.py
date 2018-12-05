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


import ConfigParser
import os

class ConfigManager:
    """Class for load config from file."""

    def get(self, section, key):
        """Get config from config file"""
        config = ConfigParser.ConfigParser()
        file_root = os.path.dirname(__file__)
        path = os.path.join(file_root, 'DynamicConfig.conf')
        config.read(path)
        return config.get(section, key)