#!/usr/bin/env python
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

"""
Author: Tencent
Date:   Otc 08, 2018
Description: IoT Threat Intelligence Analysis System
"""

import os
import sys
import subprocess
import argparse
import json
import hashlib
from conf import *
from common import *

def is_packed_upx(file_path):
    output, ret = check_output([UPX_EXECUTABLE_FILE_PATH, "-q", "-t", file_path])
    if -1 != output.find(b"[OK]"):
        return True
    return False

def unpack_upx(file_path):
    output, ret = check_output([UPX_EXECUTABLE_FILE_PATH, "-q", "-d", file_path])
    if ret == 0:
        return True
    return False

def make_result_file(output_dir):
    ida_result_file_path = os.path.join(output_dir, IDA_FILE_ANALYSIS_RESULT)
    virustotal_result_file_path = os.path.join(output_dir, VIRUSTOTAL_RESULT)
    file_detail_info_path = os.path.join(output_dir, FILE_DETAIL_INFO)
    
    all_info = {}
    try:
        # IDA result
        if os.path.exists(ida_result_file_path):
            ida_result_json = json.load(open(ida_result_file_path, "r"))
            all_info.update(ida_result_json)
            os.remove(ida_result_file_path)
        else:
            #logger.error("Error: make_result_file() Cannot find file IDA_FILE_ANALYSIS_RESULT, may be something wrong in script file IDA_PYTHON_SCRIPT.")
            return 
        
        # VirusTotal result
        if os.path.exists(virustotal_result_file_path):
            vt_result_json = json.load(open(virustotal_result_file_path, "r"))
            all_info["virustotal"] = vt_result_json
            os.remove(virustotal_result_file_path)
        
        with open(file_detail_info_path, "a+") as f:
            f.write(json.dumps(all_info))
            f.write("\n")
        
    except Exception as e:
        logger.error("make_result_file error.", exc_info=True)

def get_virustotal_info(md5, output_dir):
    json_result = VTUtil.virustotal(md5, VIRUSTOTAL_KEY, 1, PROXIES)
    if len(json_result):
        with open(os.path.join(output_dir, VIRUSTOTAL_RESULT), "a+") as f:
            f.write(json.dumps(json_result, ensure_ascii=False))
            f.write("\n")

def analyze_file(sample_path, output_dir, args):
    if not os.path.exists(sample_path):
        logger.error("Error:analyze_file() file not exists.")
        return 
    
    if sample_path.endswith(".idb") or sample_path.endswith(".i64") or \
       sample_path.endswith(".log") or sample_path.endswith(".asm") or \
       sample_path.endswith(".til") or sample_path.endswith(".id0") or \
       sample_path.endswith(".id1") or sample_path.endswith(".id2") or \
       sample_path.endswith(".nam"):
        return 
    
    logger.info("%s" % (sample_path))
    
    # get file md5
    try:
        m = hashlib.md5(open(sample_path, 'rb').read())
        md5 = m.hexdigest()
    except Exception as e:
        logger.error("get file md5 error.", exc_info=True)
    
    # unpack upx
    packer = "None"
    if not os.path.isfile(UPX_EXECUTABLE_FILE_PATH):
        logger.warning("If you want to unpack UPX,you need to set UPX_EXECUTABLE_FILE_PATH in file conf.py.")
    else:
        if is_packed_upx(sample_path):
            if unpack_upx(sample_path):
                logger.info("Packed by UPX.")
                packer = "upx"
    
    # execute IDA script
    execute_ida(sample_path, output_dir, packer)
    
    # get info from VirusTotal
    if (args.virustotal or VIRUSTOTAL_ALWAYS_GET) and md5:
        get_virustotal_info(md5, output_dir)
    
    # save all results to file_detail_info.txt, delete other result files
    if args.clean:
        make_result_file(output_dir)
    
    
def execute_ida(sample_path, output_dir, packer):
    # IDA python script path
    ida_python_script_path = os.path.join(os.getcwd(), IDA_PYTHON_SCRIPT)

    # Plugin path 
    plugin_path = os.path.join(os.getcwd(), IDA_PLUGINS_DIR_NAME)

    # execute IDA
    cmd_ida = r'%s -c -A -S"%s %s %s %s" %s' % (check_path(IDA_EXECUTABLE_FILE_PATH), check_path(ida_python_script_path), check_path(plugin_path), check_path(output_dir), packer, check_path(sample_path))
    try:
        stdout, stderr = Popen(cmd_ida, shell = True)
        if stderr != None:
            logger.error("execute_ida error, check input file:%s" % sample_path)
        
        # error info
        error_log_path = os.path.join(os.path.dirname(sample_path), OTHER_ERROR_LOG)
        if os.path.exists(error_log_path):
            with open(error_log_path, "rb") as f:
                logger.error(f.read())
            os.remove(error_log_path)
    except Exception as e:
        logger.error("execute_ida error.", exc_info = True)

def analyze_dir(sample_dir, output_dir, args):
    for root,dirs,files in os.walk(sample_dir):
        for f in files:
            try:
                file_path = os.path.join(root, f)
                analyze_file(file_path, output_dir, args)
            except Exception as e:
                logger.error("analyze_dir error.", exc_info=True)
                continue

def parse_args():
    parser = argparse.ArgumentParser(description = 'Tencent IoTHunter')
    group = parser.add_mutually_exclusive_group()
    
    group.add_argument('-s', dest='sample_dir', default=None, help='samples folder path for analyzing.')
    group.add_argument('-f', dest='sample_path', default=None, help='singal sample path for analyzing.')
    parser.add_argument('-o', dest='output_dir', default=None, help='output folder path for saving analysis result and log files.')
    parser.add_argument('-v', "--virustotal", dest='virustotal', default=False, action='store_true', help='try to get the sample info from VirusTotal.')
    parser.add_argument('-c', "--clean", dest='clean', default=False, action='store_true', help='clean result files,save all results to %s' % FILE_DETAIL_INFO)
    
    args = parser.parse_args()
    return args

def main():
    args = parse_args()
    while True:
        output_dir = RESULT_OUTPUT_DIR
        if args.output_dir:
            output_dir = os.path.abspath(args.output_dir)
            
        if not os.path.isdir(output_dir):
            print ("Invalid Path: %s" % output_dir)
            print ("ERROR: You need to set RESULT_OUTPUT_DIR in file conf.py or use -o to set this variable.")
            break
        
        global logger
        logger = enable_logging(IOT_HUNTER_LOGGER_NAME, os.path.join(output_dir, IOT_HUNTER_LOG))
        
        if not os.path.isfile(IDA_EXECUTABLE_FILE_PATH):
            logger.error("ERROR: You need to set IDA_EXECUTABLE_FILE_PATH in file conf.py.")
            break
            
        if IDA_FILE_ANALYSIS_LOG == "":
            logger.error("ERROR: You need to set IDA_FILE_ANALYSIS_LOG in file conf.py.")
            break
            
        if IDA_FILE_ANALYSIS_RESULT == "":
            logger.error("ERROR: You need to set IDA_FILE_ANALYSIS_RESULT in file conf.py.")
            break
            
        if IOT_HUNTER_LOGGER_NAME == "":
            logger.error("ERROR: You need to set IOT_HUNTER_LOGGER_NAME in file conf.py.")
            break
            
        if IOT_HUNTER_LOG == "":
            logger.error("ERROR: You need to set IOT_HUNTER_LOG in file conf.py.")
            break
        
        if (args.virustotal or VIRUSTOTAL_ALWAYS_GET) and VIRUSTOTAL_KEY == "":
            logger.error("ERROR: You need to set VIRUSTOTAL_KEY in file conf.py.")
            break
            
        if args.clean and FILE_DETAIL_INFO == "":
            logger.error("ERROR: You need to set FILE_DETAIL_INFO in file conf.py")
            break
        
        if args.sample_path:
            if not os.path.isfile(args.sample_path):
                logger.error("Invalid File Path: %s" % args.sample_path)
                logger.error("ERROR: You need to check this file path.")
                break
            analyze_file(args.sample_path, output_dir, args)
            break
            
        sample_dir = MAL_SAMPLES_DIR
        if args.sample_dir:
            sample_dir = os.path.abspath(args.sample_dir)
        
        if not os.path.isdir(sample_dir):
            logger.error("Invalid Path: %s" % sample_dir)
            logger.error("ERROR: You need to set MAL_SAMPLES_DIR in file conf.py or use -s to set this variable.")
            break
        
        logger.info("Sample Dir: %s" % (sample_dir))
        logger.info("Output Dir: %s" % (output_dir))
        analyze_dir(sample_dir, output_dir, args)
        
        break
        
if __name__ == '__main__':
    main()
