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

import os
import DynamicPlugins


class DynamicPluginManager():
    """Dynamic Analysis Plugin manager."""

    def __init__(self):
        self.plugin_folder = '\\DynamicPlugins\\'

    def get_all_plugins(self):
        """Get All plugins in plugins folders
        
        return:
            plugin list.
        """
        path = __file__
        plugin_path = os.path.split(path)[0] + self.plugin_folder
        files = os.listdir(plugin_path)
        plugins = []
        for plug_file in files:
            if len(plug_file) > 3:
                if plug_file[-3:] == '.py' and '__init__' not in plug_file:
                    plugins.append(plug_file)
        return plugins

if __name__ == '__main__':
    plugin_manager = DynamicPluginManager()
    print (plugin_manager.get_all_plugins())


