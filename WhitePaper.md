# HaboMalHunter: An Automated Malware Analysis Tool for Linux ELF Files

Jingyu YANG,Zhao LIU, Wei ZHANG, Xu WANG, Guize LIU

## ABSTRACT

HaboMalHunter is an automated malware analysis tool for Linux ELF files, which is a sub-project of Habo Analysis System independently developed by Tencent Antivirus Laboratory. It can comprehensively analyze samples from both static information and dynamic behaviors, trigger and capture behaviors of the samples in the sandbox and output the results in various formats. The generated report reveals significant information about process, file I/O , network and system calls. 

Recently, HaboMalHunter has opened its source code under the MIT license, aimed to share and discuss the automatic analysis technology with researchers alike. The project applies digital forensics techniques, such as kernel space system call tracing and memory analysis, and it emphasizes the importance of collaboration with mainstream security tools by making it easy to add third-party YARA rules and supporting the output of .mdb files that are hash-based signature of the ClamAV. The tool, by generating a .syscall file containing a system call number sequence, is also friendly to artificial intelligence research on malware classification and detection.

HaboMalHunter has also been deployed and validated with a large-scale cluster at Tencent Antivirus Laboratory. With the processing ability of thousands of ELF malware samples per day, most of which are from the VirusTotal, HaboMalHunter helps security analysts extract static and dynamic features effectively and efficiently.

We hope to present the technical architecture and the detailed implementation about HaboMalHunter and to demonstrate it with several typical real-world Linux malware samples.

For more information, please read the white paper and visit the project website at:

https://github.com/Tencent/HaboMalHunter
 
# 1. Introduction

HaboMalHunter was developed against the backdrop that few automatic malware analysis tools were designed for the Linux platform. It uses virtual machine execution and monitoring technology to analyze the behaviors of ELF samples through an automated analysis process, providing an efficient solution for antivirus researchers.

This paper introduces the analysis flow of HaboMalHunter, elaborates on its architecture, implementation and demonstration, and outlines its advantages compared with similar projects.
 
Research on Linux malware has practical implications. Although the quantity of Linux malware is comparatively small, Linux is the most widely used operating system by servers. Once a Linux server is infected, a great many enterprises and their users may be affected, causing immeasurable direct and indirect losses. In fact, malware targeting at enterprise servers has appeared in the public view in recent years. Some of the malicious activities can steal sensitive data in the servers, and some can use the server resources to make DDoS or other malicious attacks, and even APT attacks on specific businesses have occurred. As a result, the study of Linux malware has become more urgent than ever.

# 2. Architecture and Implementation

At the beginning of the analysis stage, HaboMalHunter will initialize the runtime environment, such as restoring the virtual machine image to its original state and copying the sample file onto the virtual machine. Then static and dynamic analysis will be conducted. Lastly, HaboMalHunter will generate results in different formats as requested.

## 2.1. Static analysis

Static analysis refers to the analysis process of collecting the characteristics of a sample without running it. HaboMalHunter collects the characteristics of the sample, including the file format, hash value, ELF file features, YARA [1] result, the string information and other features. As with the data, significant data are the features conducive to the analysis of malware, such as IP address and the source file name. 

HaboMalHunter emphasizes its integration with mainstream security tools. It contains YARA rules written by security analysts. Besides, HaboMalHunter supports the output of .mdb files, which are hash based signature of ClamAV [2].

## 2.2. Dynamic analysis

### 2.2.1 Preparation

Before running a sample, HaboMalHunter will launch some monitoring programs, such as Tcpdump[3] to monitor network communication and Sysdig[4] to monitor system calls (including process creation, file read and write operations, etc.). These monitoring tools will record the monitored data during execution. After the analysis process ends, the monitored data and logs of various monitoring tools will be processed.

### 2.2.2 Execution

After the runtime environment is set up, HaboMalHunter will load the sample with the loader program. The reason for using loader is that the monitoring program needs to acquire the process ID (PID) of the sample for monitoring tasks. The loader can first create the process and get its PID, and after the monitoring program is set, HaboMalHunter will send the continuing execution signal (SIGCONT) to loader to continue execute the sample. When the sample is executed, the execution time limitation is set based on the configuration file in order to wait for more malicious actions.

### 2.2.3 Memory Analysis

After the execution has been finished, HaboMalHunter will first use LiME [5] to get memory dump file. The tool is a kernel driver that can dump the current physical memory to a specified disk file. HaboMalHunter then uses volatility[6] to analyze the saved memory image and output the process information and shell execution records. Because such information is derived based on the data structures in memory, it can be used to resist the process hiding techniques such as Direct Kernel Object Manipulation (DKOM) [7].

### 2.2.4 Log Processing

In this phase, the monitored data and logs obtained before can be summarized. HaboMalHunter contains a variety of log output format. HaboMalHunter also designs a hierarchical structure to simplify the extracted information. For example, the self-delete action is corresponds to a file delete operation while the deleted target is the sample itself.

HaboMalHunter can also output different results as requested. Regarding the machine learning, HaboMalHunter can output the system call sequence as the array format (. syscall file); Regarding automated malware detection, HaboMalHunter can output log as json format ; HaboMalHunter can also provide a HTML report to simplify the contents of the report to ensure readability.

# 3. Demonstration

Linux.BackDoor.Gates is a type of DDoS malware on Linux platform. It has a long history, clever hidden methods and significant network attack behaviors. The main malicious feature is that it has the backdoor and DDoS attack capabilities and can replace the commonly used system files to remain under cover.

Linux.BackDoor.Gates encrypts the significant data, such as command and control (C&C) address and port, making it difficult to be detected only based on static features. At this point, using HaboMalHunter can easily capture its actions in the runtime, including the connected C&C domain name and port information.

The following result is generated by HaboMalHunter for Linux.BackDoor.Gates.6.

## 3.1. Autorun
 
The malware inserts an autorun file into the directory /etc/init.d/:

```

	execve: -c ln -s /etc/init.d/VsystemsshMdt /etc/rc1.d/S97VsystemsshMdt
	execve: -c ln -s /etc/init.d/VsystemsshMdt /etc/rc5.d/S97VsystemsshMdt
	
```

## 3.2. Self Replication

The malware copies itself to /usr/bin/bsd-port directory, and rename it as `knerl`, a misspell of `kernel` , to achieve the purpose of hiding itself:

```

	execve: -c mkdir -p /usr/bin/bsd-port
	execve: -c cp -f /tmp/bin/****.elf /usr/bin/bsd-port/knerl

```

## 3.3. Network Traffic

The malware sends a request to query a domain of bei[.]game918[.]me and then tries to create a TCP connection on port 21351 after obtaining the IP address:

```

	Behaviour:	Query dns
	Detail info:	192.168.0.** -> 8.8.8.8 DNS 76 Standard query 0x16e9 A bei.game918.me
	
	Behaviour:	Respond dns
	Detail info:	8.8.8.8 -> 192.168.0.** DNS 92 Standard query response 0x16e9 A **.133.40.**
	
	Behaviour:	TCP package
	Detail info:	192.168.0.** s-> **.133.40.** TCP 76 60159 > 21351 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 TSval=12750 TSecr=0 WS=128
	**.133.40.** -> 192.168.0.** TCP 56 21351 > 60159 [RST, ACK] Seq=1 Ack=1 Win=0 Len=0

```


# 4. Related Work

In antivirus field, there are currently some well-known analysis systems, which can be classified into proprietary systems and open source systems.

As for the proprietary systems, Fireeye[8] provides a professional hardware environment for malware analysis (AX series). The use of the hardware environment can make the analysis more efficient and reduce environmental impact factors. In addition, VxStream Sandbox[9] provides the function of simulating the user operation. However, neither of the two systems has the ability to analyze ELF malware. Moreover, as proprietary systems, they are not as responsive to new features as open-source systems. By contrast, open sourced HaboMalHunter can be quickly integrated with other security tools, for example, analysts can extract YARA or ClamAV rules based on analysis results. HaboMalHunter also supports a variety of environments, which means it is more applicable than solutions using the customized hardware.

Within the open source systems, Cuckoo Sandbox[10] is widely used for online file analysis websites, such as malwr.com. However, the website does not support ELF file so far. In contrast, HaboMalHunter project has been deployed to the back-end of Habo website (https://habo.qq.com), with which users can upload ELF files and obtain the behaviors and detection results. In addition, there is an open source project for the automated analysis in Linux platform, namely Limon Sandbox [11]. This system uses Strace to launch sample files. In contrast, HaboMalHunter uses the loader technology to ensures that the sample can be monitored by multiple tools at the same time.

# 5. Conclusion

Considering the importance of the Linux platform and the damage caused by malware, a tool for automated analysis of Linux ELF files is very useful. HaboMalHunter can comprehensively analyze samples from both their static and dynamic features and output actions reports in a variety of formats. Meanwhile, it can be easily integrated with the existing security tools and provide data for machine learning. By using it to analyze Linux.BackDoor.Gates virus and comparing it with other similar projects, it indicates that HaboMalHunter has shown great flexibility, strong adaptability and is suitable for the automated analysis of ELF files.

# References

1. YARA: The pattern matching swiss knife for malware researchers, http://virustotal.github.io/yara/
2. Kojm, Tomasz. "Clam AntiVirus User Manual." (2012).
3. Jacobson V, Leres C, McCanne S. The tcpdump manual page[J]. Lawrence Berkeley Laboratory, Berkeley, CA, 1989, 143.
4. DRAIOS INC. sysdig, 2014. http://www.sysdig.org/
5. Sylve, J. (2012). Lime-linux memory extractor. In ShmooCon'12
6. The Volatility Foundation. Volatility frame work. https://github.com/volatilityfoundation
7. Butler, J. (2004). Dkom (direct kernel object manipulation). Black Hat Windows Security.
8. Gandotra, E., Bansal, D., & Sofat, S. (2014). Malware analysis and classification: A survey. Journal of Information Security, 2014.
9. PAYLOAD SECURITY INC,. Payload Security. https://www.hybrid-analysis.com, 2016.
10. Guarnieri, C., Tanasi, A., Bremer, J., & Schloesser, M. (2012). The cuckoo sandbox.
11. Monnappa, Automating Linux Malware Analysis Using Limon Sandbox. Black Hat 2015.