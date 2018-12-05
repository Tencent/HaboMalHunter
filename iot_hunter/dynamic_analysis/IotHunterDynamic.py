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

import argparse
import DynamicAnalyzer
import PluginManager
import os
import logging


def write_log(logname, logdata):
    """write log to file."""
    with open(logname, 'w') as f:
        f.write(logdata)

if __name__ == '__main__':
    # parse argument.
    parser = argparse.ArgumentParser()
    parser.add_argument('-f ', '--filename', help='File to Analyze')
    parser.add_argument('-d', '--file_dir', help='Files directory to Analyze')
    parser.add_argument('-o', '--out_dir', help='log output directory')
    args = parser.parse_args()

    file_list = []  # file to analyze list
    log_dir = ''  # log file path

    while True:
        if args.filename:
            file_list.append(args.filename)

        if args.file_dir:
            if os.path.isdir(args.file_dir):
                file_dir = os.path.abspath(args.file_dir)
            else:
                print ('Samples Directory is not Correct')
                break
            for fname in os.listdir(file_dir):
                file_list.append(os.path.join(file_dir, fname))

        if args.out_dir:
            if os.path.isdir(args.out_dir):
                log_dir = os.path.abspath(args.out_dir)
            else:
                print ('Log Directory is not Correct')
                break

        if len(file_list) == 0:
            print ('No file found. Please Use -f followed by filename or -d followed by directory to analyze')
            break


        for file_to_analyze in file_list:
            # init Dynamic Analyzer
            analyzer = DynamicAnalyzer.DynamicAnalyzer()
            analyzer.set_log_path(log_dir)
            analyzer.analyze_file(file_to_analyze)
            behaviors = DynamicAnalyzer.DynamicBehaviors()
            analyzer.do_log_parse(behaviors)

            # Get all plugins
            plugin_manager = PluginManager.DynamicPluginManager()

            # run every plugin
            for plugin in plugin_manager.get_all_plugins():
                plugin_name = os.path.splitext(plugin)[0]
                plugin_module = __import__(
                    "DynamicPlugins." + plugin_name, fromlist=[plugin_name])
                plugin_item = getattr(plugin_module, plugin_name)
                p = plugin_item()
                if p.analyze(behaviors) == 1:
                    behaviors.plugins_result[plugin_name] = p.get_result()

            # write report to logfile
            if log_dir != '':
                write_log(os.path.join(log_dir, os.path.split(file_to_analyze)[1] + '.json'),
                         behaviors.to_report())
        break
