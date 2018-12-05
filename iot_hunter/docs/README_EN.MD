(中文帮助请参看[这里](#readme_cn))
## Tencent IoT Hunter User Guide


## Content
I. Introduction

II. Framework features

III. Compatibility

IV. Information Extraction details

V. How to use

VI. Use Extensible Plugins

VII. Data visualization

VIII. Tools Used

IX. Future Work

## I. Introduction

Tencent IoT Hunter is a framework tool which is developed to gather IoT threat intelligence. It focus on the whole IoT malware analysis life cycle in all directions through static information extraction, dynamic information extraction, and third-party network platform information. For security researchers it is much easier to do IoT malware analysis, research, track threat by using this intelligence framework. 

Using this framework tool, the malicious information (CNC, Domain, function, etc.) within the IoT sample can be accurately and fine-grained obtained, which can be directly used to build the IoT threat cloud detection service. The advantage is that there is no need for analysts to reconfirm the malicious information, which greatly improves the efficiency of malicious information processing. 

The framework provides a good extension interface, users can write plug-ins to extend the scope of information extraction to enhance this tool. Through the extracted information, we can quickly build a IoT threat intelligence platform, quickly visual analysis, mining IoT threat families, variants and monitor threat situation.

## II. Framework features
### (I) Good extension interface
This framework provides an extension interface for security professionals using the framework to write their own plugin, to extend the scope of information extraction. 

In order to facilitate the user to write their own plugin, framework provides a foundation class, the new plugin can be directly implemented by inheriting the base class, without the need to write additional code, so that users can focus on how to do the information extraction of the target sample. 

At the same time, the framework records the detailed log. It is very easy for the user to debug the code by viewing the log file. 

when writing plugin, analysts can define their own sample family type, propagation approach, target attack device, attack method, and can accurately obtain malicious information such as CNC, Domain, weak password dictionary, control commands and so on. 

### (II) Fine-grained information extraction
In the past, some analysis tools will extract coarse-grained information from samples, and security researchers need to make a second confirmation of whether it is malicious or not before using the information. 

For example, a coarse-grained IP, is extracted from a sample, but it is not known whether the IP is malicious, so it cannot be used directly as a malicious IP, and the IP needs to be further confirmed if it is malicious. 

But this framework tool use accurate feature matching method, which can accurately extract malicious information, the malicious information can be used directly without re-confirmation.

### (III) Third-party intelligence aggregation
This framework attempts to get more IoT intelligence information through the open third-party network intelligence platform in order to provide more valuable reference information for users.

## III. Compatibility
* Python2, Python3. 
* Windows, Linux, (OS X not currently tested)

## IV. Information Extraction details
This framework supports static and dynamic information extraction of ELF files on ARM, X86, X64, MIPS, Sparc, PowerPC platforms.

### (I) Static Information
**Defined information**. 
* Virus Name
* Malware Type 
* Family information
* Spreading Method
* Target Device
* Main attacking method

**Information extraction**
* Basic Information (file size, file type, platform, md5, sha1, sha256)
* C&C Address
* Domain
* IP
* URL
* UDP
* TCP
* DNS
* Malware Configuration
* Weak Password Dictionary 
* All Strings
* Suspicious Strings 
* all function Names 
* Control Commands
* Packer information

### (II) Dynamic Information 
**Process information:**
* Process EXECVE: parameter information
* Process Clone

**File Operation information:**
* File open: file name
* File read: read data
* File write: writing data

**Socket Information:**
* Connect: ip
* Recvfrom : ip, data
* Sendto : ip, data
* Bind : ip

**Network communication information:**
* Network packets: ip, protocol
* HTTP Information: host, data
* TCP Information: ip, data
* UDP Information: ip, data
* IRC Information: ip,IRC Message

**Dynamic Analysis plug-in information:**
* Plug-in Name. 
* plug-in Analysis results

### (III) Result
All analysis results are saved in the results file as json format: 

**Static Analysis Results JSON:**

![_15435692695130](https://user-images.githubusercontent.com/17021671/49279858-94613a00-f4c3-11e8-839a-07adfb7b9943.png)
![_20181130171521](https://user-images.githubusercontent.com/17021671/49279861-975c2a80-f4c3-11e8-9884-84dd8eec0b74.png)
![_20181130171541](https://user-images.githubusercontent.com/17021671/49279865-99be8480-f4c3-11e8-8c13-a04493340229.png)

**Dynamic Analysis Results JSON:**

![2](https://user-images.githubusercontent.com/17021671/49278251-30d50d80-f4bf-11e8-9dc5-eafc0b25a0c1.png)
![3](https://user-images.githubusercontent.com/17021671/49278258-35012b00-f4bf-11e8-9e3e-b7731039b11d.png)
![4](https://user-images.githubusercontent.com/17021671/49278261-36caee80-f4bf-11e8-9c06-13a424b98ec6.png)
![5](https://user-images.githubusercontent.com/17021671/49278270-39c5df00-f4bf-11e8-89b2-903215ce3e5a.png)

## V. How to use
#### (I) Static Information Extraction Tool
This tool can be set parameters using the command line or by a configuration file.
```
iot_hunter.py -h
usage: iot_hunter.py [-h] [-s SAMPLE_DIR | -f SAMPLE_PATH] [-o OUTPUT_DIR]
                     [-v] [-c]

Tencent IoT Hunter

optional arguments:
  -h, --help        show this help message and exit
  -s SAMPLE_DIR   samples folder path for analyzing.
  -f SAMPLE_PATH  singal sample path for analyzing.
  -o OUTPUT_DIR  output folder path for saving analysis result and log files.
  -v, --virustotal    try to get the sample info from VirusTotal.
  -c, --clean       clean result files,save all results to 
                 result_file_detail_info.txt.
```

#### 1. Setting parameters using the command Line
**Single File Analysis:**
```
iot_hunter.py -f F:\Samples\0019c77ad7f4f97ec492726e9aa8e15e -o F:\result
```

**Multi files Analysis:**
```
iot_hunter.py -s F:\Samples -o F:\result
Sample Dir: F:\Samples
Output Dir: F:\result
F:\Samples\0019c77ad7f4f97ec492726e9aa8e15e
F:\Samples\2983a7e5bc97996cd98dffd4f78e95b2
Packed by UPX.
F:\Samples2989b5de79e0ab4417c10b64738a10a0
```
**Get VirusTotal Information:**
```
iot_hunter.py -v -s F:\Samples -o F:\result
```
**Load results to Elasticsearch:**
```
import_data_to_es.py -r F:\result\result_ida_file_analysis.txt
```
#### 2．Use config file: conf.py
```
MAL_SAMPLES_DIR = r"F:\Samples"
RESULT_OUTPUT_DIR = r"F:\result"
```
Run python script:
```
python iot_hunter.py 
```
#### 3．Configuration File (conf.py) Parameter description

**Parameters that must be set:**
```
IDA PRO Path:https://www.hex-rays.com
IDA_EXECUTABLE_FILE_PATH = r"C:\Program Files (x86)\IDA 6.5\idaq.exe"
```
**On-demand configuration:**
```
Samples Directory
MAL_SAMPLES_DIR = r"F:\Samples"

Result Output Directory
RESULT_OUTPUT_DIR = r"F:\result"

UPX Tool Path:https://github.com/upx/upx-testsuite
UPX_EXECUTABLE_FILE_PATH = r"f:\tools\upx\i386-win32.pe\upx-3.95.exe"

VirusTotal key:https://www.virustotal.com
VIRUSTOTAL_KEY = "676xxxxxxxxxxxxxxxxxxxxxxxxxxxxx7d1db"

If visit VirusTotal need Proxy,Please use the following code
PROXIES = {"http": "proxy.xxxx.com:8080", "https": "proxy.xxxx.com:8080"}

If you always try to get VirustTotal Information,Please set this parameter to True
VIRUSTOTAL_ALWAYS_GET = False

File Size Limit
FILE_SIZE_LIMIT = 10 * 1024 * 1024

Elasticsearch parameters:https://github.com/elastic/elasticsearch-py
ES_HOST = "localhost:9200"
ES_INDEX_NAME = "iot_threat"
ES_TYPE_NAME = "FileAnalysis"
```
**Default configuration:**
```
IDA Script Analysis File Result
IDA_FILE_ANALYSIS_RESULT = r"result_ida_file_analysis.txt"

VirusTotal Information File Name
VIRUSTOTAL_RESULT = r"result_virustotal.txt"

Summary of all results（IDA + VirusTotal）,Need use -c in commmand line.
FILE_DETAIL_INFO = r"result_file_detail_info.txt"

Log File Configuration
IDA_ANALYSIS_LOGGER_NAME = "IDA_ANALYSIS_FILE"
IDA_FILE_ANALYSIS_LOG = r"log_ida_file_analysis.log"
IOT_HUNTER_LOGGER_NAME = "IOT_HUNTER_MAIN"
IOT_HUNTER_LOG = r"log_iot_hunter.log"
OTHER_ERROR_LOG = r"log_other_error.log"
ES_LOGGER_NAME = "IMPORT_DATA_TO_ES"
ES_IMPORT_DATA_LOG = "log_import_data_to_es.log"

Parameters used internally, try not to modify them. 
If you want to modify, you need to modify both the associated file name and the directory name
IDA_PYTHON_SCRIPT = "ida_analysis_file.py"
IDA_PLUGINS_DIR_NAME = "plugins"
```
### （二）Dynamic Analysis Tool

#### 1．Analysis Environment Setup

The dynamic analysis environment needs to run the IOT sample in the virtual machine environment and monitor its behavior. For safety the IOT sample execution environment needs the virtual machine. This dynamic analysis tool is based on the VirtualBox. One Linux guest VM should be installed such as (Ubuntu).

**Guest VM Installation:**

1.Linux System,VBoxGuestAdditions_5.2.22

2.QEMU,Use QEMU User Mode to emulate ARM, MIPS, PowerPC Iot files in x86/64 platform

3.Strace:monitor sample behaviors information

4.Tcpdump: capture network packets for analysis

5.Clean System with above tools, please use root account and save a snapshot named "analysis"

**Host OS tools:**

1.Tshark:To analyze packets file capture by tcpdump

#### 2．Analysis Tool Configuration

Configuration File:DynamicConfig.conf
```
[guest_vm]
# Guest os configuration, username, password,vm name
name=ubuntu11.04
username=root
password=root

#sample to run path
runpath=/home/root/Desktop/

#host os path to put strace log and tcpdump pcap file
host_log_path=f:\vm_share\strace.log
host_log_tcpdump=f:\vm_share\tcpdump.pcap

#guest os path to put strace, tcpdump, guestanalyzer.py
vm_log_path=/home/justin/Desktop/strace.log
vm_log_tcpdump=/home/justin/Desktop/tcpdump.pcap
guest_analyzer_path=/home/justin/Desktop

[vbox]
virtualbox_path = D:\Program Files\Oracle\VirtualBox

[analyzer]
max_strace_lines=20000
strace_log_path=f:\vm_share\strace.log
tshark_path=c:\Program Files\Wireshark\tshark.exe
host_log_tcpdump=f:\vm_share\tcpdump.pcap
```
#### 3．Dynamic Analysis Tool Usage

**Single File Analysis:** ```IotHunterDynamic.py –f filename –d logdir```

**File Directory Analysis:** ```IotHunterDynamic.py –f directory –d logdir```
```
IotHunterDynamic.py -h
usage: IotHunterDynamic.py [-h] [-f  FILENAME] [-d FILE_DIR] [-o OUT_DIR]

optional arguments:
  -h, --help            show this help message and exit
  -f  FILENAME, --filename FILENAME
                        File to Analyze
  -d FILE_DIR, --file_dir FILE_DIR
                        Files directory to Analyze
  -o OUT_DIR, --out_dir OUT_DIR
                        log output directory
```
**Analysis Steps**

1.Get Sample to Analyze

2.Start Analysis VM

3.Send file to VM

4.Send Analysis Tool to VM

5.Run Target File, monitor behaviors

6.Fetch results from VM

7.Analyze log to get file,network,process information

8.Apply user plugins

9.Generate final json report

## VI. Use Extensible Plugins

### (I)Write Static Analysis Plugin
Users can write their own information extraction plugin, then put the plugin in plugins directory, which can be directly executed.

The framework provides the base class PluginParent, which provides the basic information:
```
class PluginParent():
    malicious_type = []
    malicious_family = []
    spread_way = []
    attack_device = []
    main_function = []
    cnc = []
    ip = []
    domain = []
    url = []
    udp = []
    tcp = []
    dns = []
    configuration = []
    weak_password = []
    suspicious_string = []
    bot_command = []
    other_info = []
    
    detect = ENUM_DETECT_RESULT["UNKNOW"]
    virus_name = ""
    
    __metaclass__ = ABCMeta
    @abstractmethod
    def analyze(self, *argv):
        return False
```
Plugin needs to inherit the PluginParent class and implement the analyze function, which populates the required fields by calling add_plugin (derived class name) at the end of the code:
```
import re
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
        self.get_configuration(key)
        self.get_cnc()
        self.get_weak_password(key)
        ...
            
    def get_cnc():
        ...

    def get_weak_password(self, key):
        ...

add_plugin(MiraiARM)
```
### (II). Static Plugin Debug

Because IDAPython command line calls automatically exits when it encounters an exception, and does not save code exception information, it is very inconvenient for users who write plugin to locate their own code problems. 

This framework provides the log record,  user can view the log to locate the exception problems.

log_ida_file_analysis.log:

![14](https://user-images.githubusercontent.com/17021671/49281660-0e93bd80-f4c8-11e8-98e8-eadf3245fc59.png)

User can use logger.info("xxx") to print own log information.

### (III). Write Dynamic Plugin

Users can write their own dynamic  plugin, put the plugin in DynamicPlugins directory, which can be directly executed.

Plugin development: Plugin need to implement analyze and get_result two interfaces, analysis framework will call all plugins, and generate plug-in results.  Function analyze parameter behaviors records the behavior information of the sample. Users can perform custom analysis to obtain wanted results.

Plugin Example:Get All Connected IP
```
class GetConnectIP():
    """plugin to get connect ip list"""
    def __init__(self):
        self.ip_list = []
    def analyze(self, behaviors):
        hit = 0        
        for data in behaviors.socket_log['connect']:
            hit = 1
            addr = data['addr']
            if addr not in self.ip_list:
                self.ip_list.append(data['addr'])
        return hit
    def get_result(self):
        return self.ip_list
```

## VII. Data visualization
The framework provides the function of importing analysis data into Elasticsearch, and users can quickly build a IoT data mining platform to carry out data visualization analysis. IoT family variants, spread methods, activity, new weak password can be quickly mining.

### (I). ES Data Query

![6](https://user-images.githubusercontent.com/17021671/49278295-4cd8af00-f4bf-11e8-83d5-49b18fd0f046.png)

### (II). Weak Password Tag Cloud

By extracting the weak passwords used in the IoT sample, we can observe which weak passwords are used most frequently. 

To monitor all known weak passwords, when a new weak password is found, it is very likely that a new variant or a new weak password vulnerability appears.

![7](https://user-images.githubusercontent.com/17021671/49278298-4ea27280-f4bf-11e8-80db-5fd5e281cb7a.png)

### (III). C&C Geographic location visualization
By extracting the CNC address, the address location associated with the IoT family can be obtained.
![8](https://user-images.githubusercontent.com/17021671/49278303-519d6300-f4bf-11e8-872e-6e40a66e75f4.png)

### (IV). Malware Variants Mining

Through some keywords to carry on the mining, different malware family can be clustered.

![9](https://user-images.githubusercontent.com/17021671/49278312-54985380-f4bf-11e8-83c9-1f97b824231a.png)

## VIII. Tools Used

* IDA(https://www.hex-rays.com)

* IDA Python(https://github.com/idapython/src)

* UPX(https://github.com/upx/upx-testsuite)

* VirusTotal(https://www.virustotal.com)

* Elasticsearch(https://github.com/elastic/elasticsearch-py)

* Kibana(https://www.elastic.co/downloads)

* QEMU(https://www.qemu.org/)

* VirtualBox(https://www.virtualbox.org/)

* Strace(https://strace.io/)

* Tcpdump(http://www.tcpdump.org/)

* Wireshark(https://www.wireshark.org/)



## IX. Future Work

* Include More plugins

* Extend capabilities to monitor new variants

* Include More third-party platform information 

* Include More Behavioral Monitoring

* More IOT environment simulation