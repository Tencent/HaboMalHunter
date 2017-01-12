#哈勃分析系统(HaboMalHunter)

[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](https://github.com/Tencent/HaboMalHunter/blob/master/LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/Tencent/HaboMalHunter/pulls)
[![Platform](https://img.shields.io/badge/Platform-Linux-brightgreen.svg)](https://github.com/Tencent/HaboMalHunter/wiki)

##功能描述

HaboMalHunter是[哈勃分析系统 (https://habo.qq.com) ](https://habo.qq.com)的开源子项目，用于Linux平台下进行自动化分析、文件安全性检测的开源工具。使用该工具能够帮助安全分析人员简洁高效的获取恶意样本的静态和动态行为特征。分析报告中提供了进程、文件、网络和系统调用等关键信息。

##功能清单

开源代码支持Linux x86/x64 平台上的ELF文件的自动化静态动态分析功能。

###静态分析

1. 基础信息：包括文件md5，名称，类型，大小和SSDEEP等信息。
2. 依赖so信息：对于动态链接的文件，输出依赖的so信息。
3. 字符串信息
4. ELF头信息，入口点
5. IP和端口信息
6. ELF段信息，节信息和hash值
7. 源文件名称

###动态分析

1. 动态运行启动结束信息：耗时等
2. 进程信息：clone系统调用，execve调用，进程创建结束等
3. 文件操作信息：打开，读取，修改，删除等文件IO操作
4. 网络信息：TCP, UDP, HTTP, HTTPS, SSL等信息 
5. 典型恶意行为：自删除，自修改和自锁定等
6. API信息：getpid, system, dup 等libc函数调用
7. syscall 序列信息

##未来规划

1. 希望使用volatility和LiME进行内存分析
2. 希望增加更多的病毒规则(./util/yara/malware)
3. 希望将输出的json数据格式转化成为HTML页面进行展示

##已知故障和错误列表

1. 分析病毒请在虚拟机环境下进行，对因运行病毒引起的任何软件安全问题，本项目不承担责任。
2. 推荐使用VirtualBox 5.1以上版本运行虚拟机。
3. 对于无法运行的ELF文件，例如so文件，哈勃分析系统默认会生成动态日志，但是里面只有无法运行的报错信息。
