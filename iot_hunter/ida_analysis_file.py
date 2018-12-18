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

from abc import ABCMeta,abstractmethod
import idc
import idautils
import idaapi
import os
import logging
import json
import hashlib
import struct
import traceback
try:
    from conf import *
    from util import *
    from enums import *
except ImportError as e:
    path = os.path.join(os.getcwd(), OTHER_ERROR_LOG)
    traceback.print_exc(file = open(path, "w+"))

class PluginParent():
    # Botnet  
    malicious_type = []
    # mirai gafgyt
    malicious_family = []
    # weak password, vulnerability
    spread_way = []
    # router  camera  DVR  Printer  TVBox
    attack_device = []
    # DDoS  Mining  BackDoor
    main_function = []
    # CNC: [["ip":"prot"],["ip":"prot"]]
    cnc = []
    # IP: [["ip":"prot"],["ip":"prot"]]
    ip = []
    # domain
    domain = []
    # URL
    url = []
    # UDP
    udp = []
    # TCP
    tcp = []
    # DNS
    dns = []
    # configuration info
    configuration = []
    # weak_password: [["root","123456"], ["admin","123456"]]
    weak_password = []
    # suspicious string
    suspicious_string = []
    # command
    bot_command = []
    # other info
    other_info = []
    
    # file property 0:unknown  1:black  2:white  3:gray  to see ENUM_DETECT_RESULT
    detect = ENUM_DETECT_RESULT["UNKNOWN"]
    # virua name
    virus_name = ""
    
    __metaclass__ = ABCMeta
    @abstractmethod
    def analyze(self, *argv):
        return False
        
def enable_logging(name, output_path):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    fileHandler = logging.FileHandler(output_path)
    fileHandler.setLevel(logging.DEBUG)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setLevel(logging.DEBUG)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fileHandler.setFormatter(formatter)
    formatter = logging.Formatter('%(message)s')
    consoleHandler.setFormatter(formatter)

    logger.addHandler(fileHandler)
    logger.addHandler(consoleHandler)
    return logger
    
def add_plugin(cClass):
    global plugins
    plugins.append(cClass)

def load_plugins(path):
    if not os.path.isdir(path):
        return False
        
    for root,dirs,files in os.walk(path):
        for f in files:
            file_path = os.path.join(root, f)
            logger.info("Load plugin:%s" % file_path)
            try:
                exec open(file_path, 'r') in globals(), globals()
            except Exception as e:
                logger.error('Error loading plugin: %s' % file_path, exc_info = True)

class FileInfo:
    def __init__(self):
        self.file_size = 0
        self.file_type = ""
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
        self.machine_arch = ""
        self.packer = ""
        
        self.string = []
        self.function = []
        
    def analyze(self, file_path):
        ret = False
        while True:
            try:
                self.file_size = os.stat(file_path).st_size
                if self.file_size > FILE_SIZE_LIMIT or self.file_size <= 0:
                    break
                    
                file_data = self.read_file_data(file_path)
                if file_data == None:
                    break
                    
                self.file_type = self.get_file_type(file_data)
                if self.file_type != "elf":
                    break
                    
                self.md5, self.sha1, self.sha256 = self.generate_hashes(file_data)
                self.get_machine_arch(file_data)
                
                self.get_strings()
                self.get_functions()
                
                ret = True
            except Exception as e:
                logger.error("FileInfo:analyze Error.", exc_info = True)
                
            break
        return ret
        
    def get_machine_arch(self, file_data):
        if file_data == None:
            return ""
            
        word_data = file_data[18:20]
        flag_bytes = struct.unpack('<1H', word_data)
        for i in ENUM_ELF_E_MACHINE.items():
            if i[1] == flag_bytes[0]:
                self.machine_arch = i[0]
                
    def generate_hashes(self, file_data):
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            md5.update(file_data)
            sha1.update(file_data)
            sha256.update(file_data)
            return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
        except Exception as e:
            logger.error("generate_hashes Error.", exc_info = True)
            return 0, 0, 0
            
    def read_file_data(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error("Cannot open file %s (access denied)" % file_path, exc_info = True)
            return None
    
    def get_file_type(self, file_data):
        if file_data == None:
            return ""
            
        word_data = file_data[0:2]
        flag_bytes = struct.unpack('<1H', word_data)
        if flag_bytes[0] == 0x5A4D:
            return 'exe'
        if flag_bytes[0] == 0x4B50:
            return 'zip'
        if flag_bytes[0] == 0x7A37:
            return '7z'
        if flag_bytes[0] == 0x8B1F:
            return 'gzip'
            
        dword_data = file_data[0:4]
        flag_bytes = struct.unpack('<1I', dword_data)
        if flag_bytes[0] == 0xE011CFD0:
            return 'doc'
        if flag_bytes[0] == 0x21726152:
            return 'rar'
        if flag_bytes[0] == 0x46445025:
            return  'pdf'
        if flag_bytes[0] == 0x4643534d:
            return  'cab'
        if flag_bytes[0] == 0x74725c7b:
            return  'rtf'
        if flag_bytes[0] == 0x464c457f:
            return  'elf'
            
    def get_strings(self):
        for s in Strings():
            string = str(s)
            if self.is_good_string(string):
                self.string.append(string)
            else:
                self.string.append(StringUtil.format_data_to_string(string, s.length))
        
    def get_functions(self):
        for func in Functions():
            name = GetFunctionName(func)
            if self.is_good_string(str(name)):
                self.function.append(str(name))
            else:
                self.function.append(StringUtil.format_data_to_string(str(name), name.length))
    
    def is_good_string(self, string):
        try:
            string.encode('utf-8')
        except:
            return False
        return True
        
def dump_json(json_path, file_obj, plugin_obj):
    if file_obj == None:
        return False
    
    all_info = dict(
        file_size = file_obj.file_size,
        file_type = file_obj.file_type,
        md5 = file_obj.md5,
        sha1 = file_obj.sha1,
        sha256 = file_obj.sha256,
        machine_arch = file_obj.machine_arch,
        string = file_obj.string,
        function = file_obj.function,
        packer = file_obj.packer
        )
    
    if plugin_obj == None:
        all_info.update(dict(
            malicious_type = [],
            malicious_family = [],
            spread_way = [],
            attack_device = [],
            main_function = [],
            cnc = [],
            ip = [],
            domain = [],
            url = [],
            udp = [],
            tcp = [],
            dns = [],
            configuration = [],
            weak_password = [],
            suspicious_string = [],
            bot_command = [],
            other_info = [],
            detect = ENUM_DETECT_RESULT["UNKNOWN"],
            virus_name = ""
        ))
    else:
        all_info.update(dict(
            malicious_type = plugin_obj.malicious_type,
            malicious_family = plugin_obj.malicious_family,
            spread_way = plugin_obj.spread_way,
            attack_device = plugin_obj.attack_device,
            main_function = plugin_obj.main_function,
            cnc = plugin_obj.cnc,
            ip = plugin_obj.ip,
            domain = plugin_obj.domain,
            url = plugin_obj.url,
            udp = plugin_obj.udp,
            tcp = plugin_obj.tcp,
            dns = plugin_obj.dns,
            configuration = plugin_obj.configuration,
            weak_password = plugin_obj.weak_password,
            suspicious_string = plugin_obj.suspicious_string,
            bot_command = plugin_obj.bot_command,
            other_info = plugin_obj.other_info,
            detect = plugin_obj.detect,
            virus_name = plugin_obj.virus_name
        ))
    
    with open(json_path, "a+") as f:
        f.write(json.dumps(all_info))
        f.write("\n")

def analyze(plugin_path, output_dir, sample_path, packer):
    # Analyze file detail info
    try:
        while True:
            logger.info("="*30 + "Analyze File Begin" + "="*30)
            logger.info("Sample Path:%s" % sample_path)
            
            # File basic info
            file_obj = FileInfo()
            if not file_obj.analyze(sample_path):
                logger.info("Do not analyze this file: Class FileInfo.")
                break
            file_obj.packer = packer
            
            # Load plugins
            global plugins
            plugins = []
            load_plugins(plugin_path)
            if len(plugins) <= 0:
                logger.error("No plugins!")
                break
            logger.info("Plugin Num:%d" % len(plugins))
            
            # Execute plugin
            is_detect = 0
            for plugin in plugins:
                plugin_obj = plugin()
                is_detect = plugin_obj.analyze(file_obj)
                logger.info("Analyze result:%d From %s" % (is_detect, str(plugin_obj)))
                if is_detect:
                    logger.info("Detected this file,the virus name is:%s" % plugin_obj.virus_name)
                    dump_json(os.path.join(output_dir, IDA_FILE_ANALYSIS_RESULT), file_obj, plugin_obj)
                    break
            
            if not is_detect:
                logger.info("Can not detect this file:%s", sample_path)
                dump_json(os.path.join(output_dir, IDA_FILE_ANALYSIS_RESULT), file_obj, None)
                
            logger.info("="*30 + "Analyze File End" + "="*32)
            break
    except Exception as e:
        logger.error('analyze()', exc_info=True)
    
def main():
    if len(idc.ARGV) <= 3:
        path = os.path.join(os.getcwd(), OTHER_ERROR_LOG)
        with open(path, "w+") as f:
            f.write("Error: %s arguments less" % IDA_PYTHON_SCRIPT)
        idc.Exit(0)
    
    idaapi.autoWait()
    try:
        # Arguments
        plugin_path = idc.ARGV[1]
        output_dir = idc.ARGV[2]
        packer = idc.ARGV[3]
        sample_path = idaapi.get_input_file_path()

        # Start log
        global logger
        logger = enable_logging(IDA_ANALYSIS_LOGGER_NAME, os.path.join(output_dir, IDA_FILE_ANALYSIS_LOG))
        
        # analyze
        analyze(plugin_path, output_dir, sample_path, packer)
        
    except:
        path = os.path.join(os.getcwd(), OTHER_ERROR_LOG)
        traceback.print_exc(file = open(path, "w+"))
        logger.error('main()', exc_info=True)
        
    idc.Exit(0)

main()