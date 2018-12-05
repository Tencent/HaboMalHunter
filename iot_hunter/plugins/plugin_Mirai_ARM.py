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

from util import *

class MiraiARM(PluginParent):
    def __init__(self):
        self.malicious_type = ["Botnet"]
        self.malicious_family = ["Mirai"]
        self.spread_way = ["SSH", "Telnet"]
        self.attack_device = ["Router", "Camera", "DVR", "Printer", "TV Box"]
        self.main_function = ["DDoS", "Downloader"]
        self.virus_name = "Trojan.Linux.Mirai.caa"
        self.configuration = []
        self.weak_password = []
        self.cnc = []
        self.detect = 0
        
    def analyze(self, *argv):
        ret = False
        while True:
            if len(argv) <= 0:
                break
                
            file_info_obj = argv[0]
            if file_info_obj.machine_arch != "EM_ARM":
                break
            
            # Feature
            key = self.find_key()
            if key == -1:
                logger.info("Can't find key")
                break
            
            self.get_configuration(key)
            self.get_cnc()
            self.get_weak_password(key)
            
            self.detect = ENUM_DETECT_RESULT["BLACK"]
            ret = True
            break
        return ret

    def find_key(self):
        strings = Strings()
        for s in strings:
            for key in range(1, 256):
                dec_str = ""
                for i in str(s):
                    dec_str += chr(ord(i) ^ key)

                for sig in ["busybox", "watchdog", "root", "admin", "resolv"]:
                    if sig in dec_str:
                        return key
        return -1

    def get_user_password_addr(self, start_addr, end_addr):
        is_find_addr = False
        user_addr = 0
        password_addr = 0
        user_password_same = False
        
        current_addr = end_addr
        while current_addr >= start_addr:
            current_addr = PrevHead(current_addr)
            
            if GetMnem(current_addr) == "LDR":
                mov_op1 = GetOpnd(current_addr, 0)
                mov_op2 = GetOpnd(current_addr, 1)
                op2_value = GetOperandValue(current_addr, 1)
                op2_type = GetOpType(current_addr, 1)
                if "R0" == mov_op1 and op2_type == o_mem:
                    user_addr = op2_value
                    if user_password_same:
                        password_addr = user_addr
                    
                if "R1" == mov_op1 and op2_type == o_mem:
                    password_addr = op2_value

            if GetMnem(current_addr) == "MOV":
                mov_op1 = GetOpnd(current_addr, 0)
                mov_op2 = GetOpnd(current_addr, 1)
                if "R1" == mov_op1 and "R0" == mov_op2:
                    user_password_same = True
            
            if GetMnem(current_addr) == "BL" and GetOperandValue(current_addr, 0) == end_addr:
                break
            
            if user_addr != 0 and password_addr != 0:
                is_find_addr = True
                break

        return is_find_addr, Dword(user_addr), Dword(password_addr)
        #ffbebdc9821222ee7954bb4bac611d57

    def get_weak_password(self, key):
        addr = 0
        pattern_list = [
                        "F0 4F 2D E9 48 B1 9F E5 00 30 9B E5 44 A1 9F E5",
                        "F0 4F 2D E9 8C 81 9F E5 00 30 98 E5 88 91 9F E5"
                        ]
        addr = IdaUtil.match_binary(addr, SEARCH_DOWN | SEARCH_NEXT, pattern_list)
        if addr != idc.BADADDR:
            xrefrm = IdaUtil.get_to_xrefs(addr)
            if len(xrefrm) <= 5:
               return False
               
            for ref in xrefrm:
                start_addr = ref - 50
                is_find_addr, user_addr, pass_addr = self.get_user_password_addr(start_addr, ref)
                
                if is_find_addr:
                    user_enc_string = IdaUtil.get_string(user_addr)
                    pass_enc_string = IdaUtil.get_string(pass_addr)
                    user_dec = self.decrypt_string(user_addr, len(user_enc_string), 0x54)
                    pass_dec = self.decrypt_string(pass_addr, len(pass_enc_string), 0x54)
                    
                    self.weak_password.append([user_dec, pass_dec])
        
    def get_configuration(self, key):
        addr = 0
        pattern_list = [
                        "F0 4F 2D E9 02 00 A0 E3", # 00096d10f7872706af8155d40ddc4dab
                        "F0 47 2D E9 02 00 A0 E3"  # 074ce8e24f75106c08515e77e13a848e
                        ]
        addr = IdaUtil.match_binary(addr, SEARCH_DOWN | SEARCH_NEXT, pattern_list)
        if addr != idc.BADADDR:
            ret = IdaUtil.get_to_xrefs(addr)
            if len(ret) != 1:
                return False
                
            func = idaapi.get_func(addr)
            
            current_addr = func.startEA
            malloc_addr = set()
            malloc_num = 0
            memcpy_addr = set()
            memcpy_num = 0
            data_info = []
            count = 0
            
            while current_addr < func.endEA:
                current_addr = idc.NextHead(current_addr)
                if GetMnem(current_addr) == "BL":
                    if count % 2 == 0:
                        malloc_addr.add(GetOperandValue(current_addr, 0))
                        malloc_num += 1
                    if count % 2 == 1:
                        memcpy_addr.add(GetOperandValue(current_addr, 0))
                        memcpy_num += 1
                        
                        data_addr = self.get_configuration_data_addr(func.startEA, current_addr)
                        data_len = self.get_configuration_data_len(func.startEA, current_addr)
                        data_info.append((data_addr, data_len))
                        
                    count += 1
                
            if len(malloc_addr) != 1 or len(memcpy_addr) != 1 or malloc_num < 20:
                return False

            for i, info in enumerate(data_info):
                dec_data = self.decrypt_data(info[0], info[1], key)
                
                if info[1] == 2 and (i == 0 or i == 1):
                    self.configuration.append(r"\x%02x\x%02x" % (dec_data[0], dec_data[1]))
                    continue
                    
                str = StringUtil.format_data_to_string(dec_data, info[1])
                self.configuration.append("%s" % (str))
            
    def get_cnc(self):
        ret = False
        while True:
            addr = 0
            pattern = "10 40 2D E9 01 00 A0 E3"
            addr = idc.FindBinary(addr, SEARCH_DOWN|SEARCH_NEXT, pattern)
            if addr == idc.BADADDR:
                break
                
            addr = idc.NextHead(addr)
            addr = idc.NextHead(addr)
            addr = idc.NextHead(addr)
            if GetMnem(addr) != "LDR":
                break
                
            cnc_addr = GetOperandValue(addr, 1)
            org_data_addr = Dword(cnc_addr)
            cnc_info = idc.GetString(org_data_addr)
            if cnc_info == None:
                # 0d2bd53469a2154a02ff08333b7ded36
                addr = idc.NextHead(addr)
                if GetMnem(addr) != "LDR":
                    break
                
                cnc_addr = GetOperandValue(addr, 1)
                ip_dword = Dword(cnc_addr)
                self.cnc.append([NetUtil.long_to_ip(ip_dword), ""])
                ret = True
                break
                
            elif NetUtil.check_ip(cnc_info):
                self.cnc.append([cnc_info, ""])
                ret = True
                break
                
            break
        return ret
            
    def decrypt_string(self, data_addr, data_len, key):
        dec_str = ""
        for i in range(0, data_len):
            dec_str += chr(Byte(data_addr + i) ^ key)
        return dec_str

    def decrypt_data(self, data_addr, data_len, key):
        dec_data = []
        for i in range(0, data_len):
            dec_data.append(Byte(data_addr + i) ^ key)
        return dec_data

    def get_configuration_data_len(self, start_addr, end_addr):
        data_len = 0
        need_find_op = ""
        
        current_addr = end_addr    
        while current_addr >= start_addr:
            current_addr = PrevHead(current_addr)
            
            if GetMnem(current_addr) == "MOV":
                mov_op1 = GetOpnd(current_addr, 0)
                mov_op2 = GetOpnd(current_addr, 1)
                op2_value = GetOperandValue(current_addr, 1)
                op2_type = GetOpType(current_addr, 1)
                
                if need_find_op == mov_op1 and op2_type == o_imm:
                    data_len = op2_value
                    break
                    
                if need_find_op == mov_op1 and op2_type == o_reg:
                    need_find_op = mov_op2
                
                if need_find_op != "":
                    continue
                
                if "R2" == mov_op1 and op2_type == o_imm:
                    data_len = op2_value
                    break
                    
                if "R2" == mov_op1 and op2_type == o_reg:
                    need_find_op = mov_op2
                    continue
        return data_len
        
    def get_configuration_data_addr(self, start_addr, end_addr):
        data_addr = 0
        
        current_addr = end_addr    
        while current_addr >= start_addr:
            current_addr = PrevHead(current_addr)
            
            if GetMnem(current_addr) == "LDR" and "R1" == GetOpnd(current_addr, 0):
                data_addr = Dword(GetOperandValue(current_addr, 1))
                break
        
        return data_addr

add_plugin(MiraiARM)
