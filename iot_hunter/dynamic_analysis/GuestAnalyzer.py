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

import os
import time
import logging
import argparse
import subprocess
import signal

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')

SAMPLE_RUN_TIME = 15


class GuestAnalyzer:
    """Dynamic Analyzer for Iot samples.

    attributes:
        qemu_cmd: qemu command.
        strace_cmd: strace command.
        tcpdump_cmd: tcpdump command.
        sample_filename: sample analyzed filename.
        strace_log: strace log list

    """

    def __init__(self, filename):
        """init GuestAnalyzer attributes."""
        self.qemu_cmd = 'qemu-arm -version'
        self.strace_cmd = 'strace -h'
        self.tcpdump_cmd = 'tcpdump --version'
        self.sample_filename = filename
        self.strace_log = []
        file_root = os.path.dirname(__file__)        
        self.strace_log_path = os.path.join(file_root, 'strace.log')
        self.tcpdump_log_path = os.path.join(file_root, 'tcpdump.pcap')

    def is_tool_installed(self, cmd):
        """check analysis tools installation."""
        ret = subprocess.call(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if ret != 0:
            logging.error('%s not installed ' % cmd)
            return False
        else:
            return True

    def init_analyze(self):
        """init analysis environment."""

        logging.debug('Init DynamicAnalyzer')
        if self.is_tool_installed(self.qemu_cmd) is False:
            return 0
        if self.is_tool_installed(self.strace_cmd) is False:
            return 0
        if self.is_tool_installed(self.tcpdump_cmd) is False:
            return 0
        return 1

    def check_analyzing_file(self):
        """check file exists."""

        if os.path.exists(self.sample_filename) is False:
            logging.debug('file not exist')
            return False
        else:
            return True

    def start_strace(self):
        """start strace to montior and write log to file."""

        self.strace_proc = subprocess.Popen(
            ['strace', '-f', '-s100','-o', self.strace_log_path, self.sample_filename], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logging.debug('start strace to run %s, pid: %s',
                      self.sample_filename, self.strace_proc.pid)

    def stop_strace(self):
        """stop strace."""
        if self.strace_proc.poll() == None:
            logging.debug('kill strace process')
            self.strace_proc.terminate()

    def start_tcpdump(self):
        """start tcpdump to capture network packet and write log file."""
        self.tcpdump_proc = subprocess.Popen(['/usr/bin/sudo tcpdump -iany --immediate-mode -U -w  %s' %
                                              self.tcpdump_log_path], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logging.debug(self.tcpdump_proc.pid)

    def stop_tcpdump(self):
        """stop tcpdump."""
        if self.tcpdump_proc.poll() == None:
            logging.debug('kill tcpdump process')
            self.tcpdump_proc.send_signal(signal.SIGINT)

    def chmod_tcpdump_logfile(self):
        """change logfile mode."""
        self.chmod_proc = subprocess.Popen(['sudo chmod 777 %s' %
                                            self.tcpdump_log_path], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        logging.debug(self.chmod_proc.pid)


if __name__ == '__main__':
    """main function

    args:
        filename: the filepath to analyze
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('filename', help='File Path to Analyze')
    args = parser.parse_args()

    while True:
        logging.debug(args.filename)
        analyzer = GuestAnalyzer(args.filename)
        if not analyzer.check_analyzing_file():
            break
        analyzer.init_analyze()
        logging.info('start analyzing %s' % analyzer.sample_filename)
        logging.debug('start analyze')
        if analyzer.start_strace() == 0:
            logging.error('Failed to run strace for file: %s' %
                          self.sample_filename)
            break
        if analyzer.start_tcpdump() == 0:
            logging.error('Failed to run tcpdump for file: %s' %
                          self.sample_filename)
            break

        time.sleep(SAMPLE_RUN_TIME)
        analyzer.stop_strace()
        analyzer.stop_tcpdump()
        analyzer.chmod_tcpdump_logfile()
        logging.debug('stop analyze')
        break
