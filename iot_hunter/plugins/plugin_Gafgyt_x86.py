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
# -*- coding: utf-8 -*-
from util import *

class GafgytX86(PluginParent):
    def __init__(self):
        self.malicious_type = []
        self.malicious_family = []
        self.attack_device = []
        self.main_function = []
        self.configuration = []
        self.bot_command = []
        self.weak_password_dict = []
        self.cnc = []
        self.suspicious_string = []
        self.detect = 0
        
    def analyze(self, *argv):
        ret = False
        while True:
            if len(argv) <= 0:
                break

            file_info_obj = argv[0]
            if file_info_obj.machine_arch != "EM_386" and file_info_obj.machine_arch != "EM_486":
                break

            user_name_listaddr = self.get_user_name_listaddr()
            if user_name_listaddr == -1:
                self.spread_way = []
            else:
                self.spread_way = ['weak password']

            user_password_listaddr = self.get_password_listaddr()

            bcnc = self.get_cnc()
            bgetpassword = self.get_weak_password(user_name_listaddr,user_password_listaddr)
            bcommand = self.get_bot_command()
            bsusstr = self.get_suspicious_string(user_name_listaddr)

            bresult = bcnc or bgetpassword or bcommand or bsusstr
            
            if bresult == 0:
                self.detect = ENUM_DETECT_RESULT["UNKNOWN"]
                break
            else:
                self.detect = ENUM_DETECT_RESULT["BLACK"]
                self.malicious_type = ["Botnet"]
                self.malicious_family = ['Gafgyt']
                self.attack_device = ["router"]
                self.main_function = ['DDoS']
                self.virus_name = "Trojan.Linux.Gafgyt.a"

                ret = True
            break

        return ret

    def get_user_name_listaddr(self):
        list_addr = -1
        usernames_list = ['usernames','Logins','tel_usernames','Telnet_Usernames','Usernames','user']
        while True:
            for ulistname in usernames_list:
                addr_usernames_list = idc.LocByName(ulistname)
                if addr_usernames_list != idc.BADADDR:
                    list_addr = addr_usernames_list
                    break
            break
        return list_addr

    def get_password_listaddr(self):
        list_addr = -1
        password_list = ['passwords','tel_passwords','Telnet_Passwords','Passwords','pass']
        while True:
            for passwordname in password_list:
                addr_password_list = idc.LocByName(passwordname)
                if addr_password_list != idc.BADADDR:
                    list_addr = addr_password_list
                    break            
            break
        return list_addr

    def get_cnc(self):
        ret = False
        addr_cnc = 0        
        addr_connection = idc.LocByName('initConnection')
        addr = NextHead(addr_connection)
        addr_max = idc.NextFunction(addr_connection)
        
        if addr_connection == idc.BADADDR:
            return ret
        if addr_max == idc.BADADDR:
            return ret

        while addr < addr_max:
            if GetMnem(addr) == "mov":
                if o_mem == GetOpType(addr, 1):
                    if "eax*4" in GetOpnd(addr,1):
                        addr_cnc_list = addr_string = idc.GetOperandValue(addr,1)
                        addr_cnc = idc.Dword(addr_cnc_list)
                        cnc_info = idc.GetString(addr_cnc)

                        if cnc_info == None:
                            addr = NextHead(addr)
                            continue
                            
                        if ":" in cnc_info:
                            port_index = cnc_info.index(":")
                            if " " in cnc_info:
                                space_index = cnc_info.index(" ")
                                ip = cnc_info[0:space_index]
                            else:
                                ip = cnc_info[0:port_index]
                            port = cnc_info[port_index+1:]
                            if NetUtil.check_ip(ip):
                                #self.cnc.append(cnc_info)
                                self.cnc.append([ip, port])
                                ret = True
                                return ret
                        else:
                            if " " in cnc_info:
                                space_index = cnc_info.index(" ")
                                ip = cnc_info[0:space_index]
                                if NetUtil.check_ip(ip):
                                    #self.cnc.append(cnc_info)
                                    self.cnc.append([ip, ""])
                                    ret = True
                                    return ret
                            if NetUtil.check_ip(cnc_info):
                                #self.cnc.append(cnc_info)
                                self.cnc.append([ip, ""])
                                ret = True
                                return ret
            addr = NextHead(addr)

        return ret
        
    def get_weak_password(self,addr_usernames_list,addr_passwords_list):
        ret = False
        addr_max = NextSeg(addr_usernames_list)
        username_ary = []

        if addr_usernames_list == idc.BADADDR:
            return ret
        if addr_max == idc.BADADDR:
            return ret
        
        while addr_usernames_list < addr_max:
            name_disasm = idc.GetDisasm(addr_usernames_list)
            if "offset" not in name_disasm:
                break
            else:
                addr_username = idc.Dword(addr_usernames_list)
                name_string = IdaUtil.get_string(addr_username)
                if " " in name_string:
                    break
                else:
                    if name_string not in username_ary:
                        username_ary.append(name_string)
                    addr_usernames_list = addr_usernames_list + 4

        password_ary = []
        if addr_passwords_list == idc.BADADDR:
            return ret
        while addr_passwords_list < addr_max:
            password_disasm = idc.GetDisasm(addr_passwords_list)
            if "offset" not in password_disasm:
                break
            else:
                addr_password = idc.Dword(addr_passwords_list)
                password_string = IdaUtil.get_string(addr_password)
                if " " in password_string: 
                    break
                else:
                    if password_string not in password_ary:
                        password_ary.append(password_string)
                    addr_passwords_list = addr_passwords_list + 4
                    
        for name in username_ary:
            for psw in password_ary:
                ret = True
                self.weak_password.append("%s:%s" % (name, psw))

        return ret          
        
    def get_bot_command(self):
        ret = False
        addr_processCmd_func = idc.LocByName('processCmd')
        addr_max = idc.NextFunction(addr_processCmd_func)
        addr_commond = addr_processCmd_func
        bot_command = []

        if addr_processCmd_func == idc.BADADDR:
            return ret
        if addr_max == idc.BADADDR:
            return ret
        
        while addr_commond < addr_max:
            if GetMnem(addr_commond) == "mov":
                if "offset a" in idc.GetDisasm(addr_commond):
                    addr_command_string = idc.GetOperandValue(addr_commond,1)
                    if len(GetString(addr_command_string)) > 1:
                        if (" " not in GetString(addr_command_string)) and ("%" not in GetString(addr_command_string)) and ("." not in GetString(addr_command_string)):
                            bot_command.append(GetString(addr_command_string))
                            self.bot_command.append(GetString(addr_command_string))
                            ret = True
            addr_commond = NextHead(addr_commond)

        return ret
                
    def get_suspicious_string(self,addr_usernames):
        ret = False
        strings = []

        if addr_usernames == idc.BADADDR:
            return ret
        start = 0
        end = 0
        for xref in idautils.XrefsTo(addr_usernames,1):
            start = idc.GetFunctionAttr(xref.frm, FUNCATTR_START)
            end = idc.GetFunctionAttr(xref.frm, FUNCATTR_END)
            break

        if start == idc.BADADDR:
            return ret
        if end == idc.BADADDR:
            return ret

        addr_string_xref = start
        while addr_string_xref < end:
            if GetMnem(addr_string_xref) == "push":
                if "offset a" in idc.GetDisasm(addr_string_xref):
                    addr_string = idc.GetOperandValue(addr_string_xref,0)
                    if GetString(addr_string) is not None:
                        if len(GetString(addr_string)) > 2:
                            sus_str = StringUtil.format_data_to_string(GetString(addr_string),len(GetString(addr_string)))
                            strings.append(sus_str)
                            self.suspicious_string.append(sus_str)
                            ret = True
            if GetMnem(addr_string_xref) == "mov":
                if "offset a" in idc.GetDisasm(addr_string_xref):
                    addr_string = idc.GetOperandValue(addr_string_xref,1)
                    if GetString(addr_string) is not None:
                        if len(GetString(addr_string)) > 2:
                            sus_str = StringUtil.format_data_to_string(GetString(addr_string),len(GetString(addr_string)))
                            strings.append(sus_str)
                            self.suspicious_string.append(sus_str)
                            ret = True
            addr_string_xref = NextHead(addr_string_xref)

        return ret      

add_plugin(GafgytX86)

