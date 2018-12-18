#
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
import requests
import logging
import subprocess

def check_output(cmd, shell = False):
    output = ""
    ret = 0
    try:
        output = subprocess.check_output(cmd, shell = shell)
    except subprocess.CalledProcessError as e:
        output = e.output
        ret = e.returncode
    return (output, ret)

def Popen(cmd, shell = False):
    stdout = ""
    stderr = ""
    try:
        proc = subprocess.Popen(cmd, shell = shell)
        (stdout, stderr) = proc.communicate()
    except subprocess.CalledProcessError as e:
        stderr = e.output
    return (stdout, stderr)
    
def enable_logging(name, output_path):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    fileHandler = logging.FileHandler(output_path)
    fileHandler.setLevel(logging.DEBUG)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fileHandler.setFormatter(formatter)
    formatter = logging.Formatter('%(message)s')
    consoleHandler.setFormatter(formatter)

    logger.addHandler(fileHandler)
    logger.addHandler(consoleHandler)
    return logger

def check_path(path):
    if " " in path:
        return "\"" + path + "\""
    return path

class VTUtil():
    @staticmethod
    def virustotal(md5, key, allinfo = 1, proxies = {}):
        if md5 == "" or key == "":
            return {}
            
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': key, 'resource': md5, 'allinfo':allinfo}
        json_response = {}
        try:
            response = requests.get(url, params = params, proxies = proxies)
            if response.status_code == 200:
                json_response = response.json()
                if json_response["response_code"] == 0:
                    return {}
            else:
                print ("Error:virustotal.response code:%d, see reason:%s" % (response.status_code, "https://developers.virustotal.com/v2.0/reference#api-responses"))
        except Exception as e:
            print ("Error:Cannot get result from VirusTotal:%s" % str(e))
        
        return json_response
