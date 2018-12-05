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

import sys
import os
import hashlib
import json
import struct
import re
import idc
import idautils
import idaapi

class NetUtil():
    @staticmethod
    def ip_to_long(ip):
        result = 0
        while True:
            if type(ip) != str:
                break
                
            ip_list = ip.split('.')
            if len(ip_list) != 4:
                break
                
            for i in range( 4 ):
                result = result + int(ip_list[i]) * 256 ** (3 - i)
                break
                
            break
        return result
    
    @staticmethod
    def long_to_ip(value):
        if type(value) != long:
            return ""
            
        floor_list = []
        yushu = value
        for i in reversed(range(4)):
            res = divmod(yushu, 256 ** i)
            floor_list.append(str(res[0]))
            yushu = res[1]
        return '.'.join(floor_list)

    @staticmethod
    def check_domain(domain):
        pass

    @staticmethod
    def check_ip(string):
        ret = False
        while True:
            if type(string) != str:
                break
                
            compile_ip = re.compile('^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
            if compile_ip.match(string):
                ret = True
                break
                
            break
        return ret

class IdaUtil():
    @staticmethod
    def is_packed_upx():
        strings = idautils.Strings()
        count = 0
        for s in strings:
            if "upx.sf.net" in str(s):
                return True
                
            if count >= 2:
                break
            count += 1
            
        return False

    @staticmethod
    def match_binary(addr, search_flag, pattern_list):
        ret_addr = idc.BADADDR
        for pattern in pattern_list:
            ret_addr = idc.FindBinary(addr, search_flag, pattern)
            if ret_addr != idc.BADADDR:
                break
        return ret_addr
    
    @staticmethod
    def get_to_xrefs(ea):
        xref_set = set([])
        for xref in idautils.XrefsTo(ea, 1):
            xref_set.add(xref.frm)
        return xref_set
    
    @staticmethod
    def get_frm_xrefs(ea):
        xref_set = set([])
        for xref in idautils.XrefsFrom(ea, 1):
            xref_set.add(xref.to)
        return xref_set
    
    @staticmethod
    def get_string(addr):
        """
        idc.GetString may be return wrong length.
        For example: 00096d10f7872706af8155d40ddc4dab address 0x0001A7D4 string length 8, but idc.GetString returns 3.
        """
        string = ""
        while True:
            if idc.Byte(addr) != 0:
                string += chr(idc.Byte(addr))
            else:
                break
            addr += 1
        return string

class StringUtil():
    @staticmethod
    def format_data_to_string(data, len):
        """
        Replace invisible characters with 16 hexadecimal.
        """
        string = ""
        for i in data:
            if isinstance(i, int):
                if i in range(0, 0x20) + range(0x7F, 0xFF):
                    string += r"\x%02x" % i
                else:
                    string += chr(i)
            elif isinstance(i, str):
                if ord(i) in range(0, 0x20) + range(0x7F, 0xFF):
                    string += r"\x%02x" % ord(i)
                else:
                    string += i
        return string
