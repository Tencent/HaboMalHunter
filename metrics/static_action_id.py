#coding=utf-8
"""
Tencent is pleased to support the open source community by making HaboMalHunter available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in 
compliance with the License. You may obtain a copy of the License at

http://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software distributed under the 
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. See the License for the specific language governing permissions 
and limitations under the License.
"""
"""
Author: 
Date:	August 11, 2016
Description: Linux Malware Analysis System, Static Action ID
"""
S_ID_BEGIN = 8010000
#S_ID_actionName = 801XXXX # comment
S_ID_BASE_INFO = 8010001 # base info, 基础信息
S_ID_ENTRY_INFO = 8010002 # Entry point info, 程序加载点信息
S_ID_SO_LIST = 8010003 # so libaraies, so 文件清单
S_ID_STRING_ASCII = 8010004 # ascii strings, ascii 字符串列表
S_ID_STRING_UTF16 = 8010005 # utf16 littlendian, utf16 字符串列表
S_ID_ELF_HEADER = 8010006 # readelf -h, ELF 头部信息
S_ID_ELF_SECTIONS = 8010007 # readelf -D, ELF sections
S_ID_ELF_SEGMENTS = 8010008 # readelf -l, ELF segments
S_ID_ELF_DYNSYM = 8010009 # readelf -s, ELF symbols
S_ID_Import_LIST = 8010010 # only import symbols, import symbols
S_ID_EXIFTOOL = 8010011 # exiftool, exiftool 信息
S_ID_MAGIC_LITERAL = 8010012 # file tull info
S_ID_FILE_SIZE = 8010013 # file size
S_ID_SUB_BASE_INFO = 8010014 # sub base info
S_ID_LD_IMPORT = 8010015 # import info from LD_DEBUG
S_ID_ELF_SEGMENTS_MAP = 8010016 # segments and sections mapping info
# add OCT 20, 2016
S_ID_IP_INFO = 8010017 # ip info from strings
# add NOV 10, 2016
S_ID_YARA_INFO = 8010018 # yara info
S_ID_SRC_FILE_INFO = 8010019 # source file info
# add Nov 18, 2016
S_ID_PACKER_INFO = 8010020 # packer such as upx info
# add Nov 21, 2016
S_ID_MDB_INFO = 8010021 # mdb info for section hash
S_ID_END = 8019999