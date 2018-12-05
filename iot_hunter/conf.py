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


##############[General Variables]####################################################
# Set the IDA executable file path.
IDA_EXECUTABLE_FILE_PATH = r""

# Samples folder path for analyzing.You can also use -s to set MAL_SAMPLES_DIR variable.
MAL_SAMPLES_DIR = r""

# Output folder path for saving analysis result.You can also use -o to set RESULT_OUTPUT_DIR variable.
RESULT_OUTPUT_DIR = r""

# File size limit for analyzing
FILE_SIZE_LIMIT = 10 * 1024 * 1024

# analysis result file
IDA_FILE_ANALYSIS_RESULT = r"result_ida_file_analysis.txt"
FILE_DETAIL_INFO = r"result_file_detail_info.txt"

# logging variables
IDA_ANALYSIS_LOGGER_NAME = "IDA_ANALYSIS_FILE"
IDA_FILE_ANALYSIS_LOG = r"log_ida_file_analysis.log"
IOT_HUNTER_LOGGER_NAME = "IOT_HUNTER_MAIN"
IOT_HUNTER_LOG = r"log_iot_hunter.log"
OTHER_ERROR_LOG = r"log_other_error.log"

##############[Tools Variables]######################################################
# UPX executable file from https://github.com/upx/upx-testsuite
UPX_EXECUTABLE_FILE_PATH = r""

##############[VirusTotal Variables]#################################################
# VirusTotal key from https://www.virustotal.com
VIRUSTOTAL_KEY = ""

# if set this variable True, always try to get VirusTotal info, no matter use -v or not.
VIRUSTOTAL_ALWAYS_GET = False

# VirusTotal result file
VIRUSTOTAL_RESULT = r"result_virustotal.txt"

# if you connect VirusTotal need to use proxy,set PROXIES
#PROXIES = {"http": "proxy.xxxx.com:8080", "https": "proxy.xxxx.com:8080"}
PROXIES = {}

##############[Elasticsearch Variables]##############################################
# Elasticsearch from https://github.com/elastic/elasticsearch-py
ES_HOST = "localhost:9200"
ES_INDEX_NAME = "iot_threat"
ES_TYPE_NAME = "FileAnalysis"
ES_LOGGER_NAME = "IMPORT_DATA_TO_ES"
ES_IMPORT_DATA_LOG = "log_import_data_to_es.log"

##############[Inner Variables]######################################################
# If you want to modify these variables, make sure that you change
# the script file name and plugins folder name at the same time.
IDA_PYTHON_SCRIPT = "ida_analysis_file.py"
IDA_PLUGINS_DIR_NAME = "plugins"
