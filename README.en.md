#HaboMalHunter: Habo Linux Malware Analysis System

[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](https://github.com/Tencent/HaboMalHunter/blob/master/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Tencent/HaboMalHunter/pulls)
[![Platform](https://img.shields.io/badge/Platform-Linux-brightgreen.svg)](https://github.com/Tencent/HaboMalHunter/wiki)

(中文版本请参看[这里](README.md))

##Introduction

HaboMalHunter is a sub-project of [Habo Malware Analysis System (https://habo.qq.com)](https://habo.qq.com), which can be used for automated malware analysis and security assessment on the Linux system. The tool help security analyst extracting the static and dynamic features from malware effectively and efficiently. The generated report provides significant information about process, file I/O, network and system calls.

##Features

The tool can be used for the static and dynamic analysis of ELF files on the Linux x86/x64 platform.

###Static analysis

1. Basic Information: md5, name, file type, size and SSDEEP.
2. SO Files Dependency: SO files information (only applied for dynamic linked files).
3. Strings Information.
4. ELF Header and Entry Point.
5. IP and PORTS
6. ELF Segment, Section and Hash.
7. Source File Names.

###Dynamic analysis
1. Starting and Termination: Time Stamps and Elapsed Time.
2. Processes Information: clone, execve and exit etc.
3. File I/O: open, read, write and delete etc.
4. Network: TCP, UDP, HTTP and HTTPS etc.
5. Typical Malicous Actions: self deletion, midification and lock.
6. API Information: getpid, system, dup and other libc functions.
7. syscall sequences.

##Screenshot

##Future Work
1. Memory Analysis.
2. More YARA rules (./utils/yara/malware/)
3. HTML output format

##Errors and Issues
1. Malware Analysis should be done inside a Virtual Machine enviroment and Intel-VT should be enabled on the host's BIOS. We shall not be liable to the damage of the analysed malware.
2. VirtualBox 5.1 is recommended.
3. The tool will also generate dynamic log, which contains one error message, for ELF files which can not be executed, such as so files.


