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

import subprocess
import time
import logging
import os
import re
import json
import shutil
import hashlib

import VMControl
import ConfigManager


class DynamicBehaviors(object):
    """Dynamic Behaviors Class"""

    def __init__(self):
        self.filename = ''
        self.md5_hash = ''
        self.file_log = {
            'read': [],
            'write': [],
            'open': [],
            'unlink':[]
        }
        self.socket_log = {
            'connect': [],
            'recvfrom': [],
            'sendto': [],
            'bind': []

        }
        self.tcp_log = []
        self.http_log = []
        self.udp_log = []
        self.irc_log = []
        self.dns_log = []
        self.file_read_data = {}
        self.recvfrom_data = {}
        self.plugins_result = {}
        self.proc_log = {
            'execve': [],
            'clone': []
        }
        self.packets = []

    def to_report(self):
        report = {
            'md5_hash': self.md5_hash,
            'filename': self.filename,
            'file_log': self.file_log,
            'socket_log': self.socket_log,
            'file_read_data': self.file_read_data,
            'recvfrom_data': self.recvfrom_data,
            'tcp_info': self.tcp_log,
            'udp_info': self.udp_log,
            'http_info': self.http_log,
            'irc_info': self.irc_log,
            'dns_info': self.dns_log,
            'plugin_info': self.plugins_result,
            'proc_info': self.proc_log,
            'packets_info':self.packets
        }
        return json.dumps(report, indent=4)


class DynamicAnalyzer:
    """Dynamic Analyzer for Iot Malware

    """

    def __init__(self):
        self.strace_log = []
        self.analyze_timeout = 10

    def init_vm(self):
        """init vm controller configuration. """
        self.vm_control = VMControl.VMController()
        self.vm_control.init_config()
        vmc = ConfigManager.ConfigManager()
        self.strace_log_max_lines = vmc.get('analyzer', 'max_strace_lines')
        self.strace_log_path = vmc.get('analyzer', 'strace_log_path')
        self.tshark_path = vmc.get('analyzer', 'tshark_path')
        self.tcpdump_log_path = vmc.get('analyzer', 'host_log_tcpdump')

    def set_log_path(self, logpath):
        """set log path"""
        self.log_path = logpath

    def parse_strace_log(self, log_path):
        """parse strace log."""
        line_count = 0
        self.strace_log_path = log_path
        with open(self.strace_log_path, 'r') as log_file:
            for line in log_file.readlines():
                self.strace_log.append(line)
                line_count = line_count + 1
                if line_count >= 20000:
                    break

    def parse_proc_log(self, behavior_obj):
        for line in self.strace_log:
            if 'execve(' in line:
                behavior_obj.proc_log['execve'].append(
                    line[line.find('execve'):-1])
            if 'clone(' in line:
                behavior_obj.proc_log['clone'].append(
                    line[line.find('clone'):-1])

    def parse_file_log(self, behavior_obj):
        """Parse file related log from strace."""
        for line in self.strace_log:
            # if 'read(' in line:
            #     behavior_obj.file_log['read'].append(
            #         line[line.find('read'):-1])
            if 'openat(' in line:
                behavior_obj.file_log['open'].append(
                    line[line.find('openat'):-1])
            if 'unlink(' in line:
                behavior_obj.file_log['unlink'].append(
                    line[line.find('unlink'):-1])
            # if 'write(' in line:
            #     behavior_obj.file_log['write'].append(
            #         line[line.find('write'):-1])

    def format_recvfrom_str(self, line, recefrom_data):
        """format recvfrom function string."""
        read_data_pattern = re.compile(r'recvfrom\(.+,.+,.+,.+,.+\)')
        read_func_find = read_data_pattern.search(line)
        if read_func_find:
            read_func_str = read_func_find.group(0)
            fd = read_func_str.split(',')[0][9:]
            read_byte = read_func_str.split(',')[1][2:-1]
            if fd != '' and read_byte != ' ':
                if recefrom_data.has_key(fd):
                    recefrom_data[fd] = recefrom_data[fd] + read_byte
                else:
                    recefrom_data[fd] = read_byte

    def format_read_str(self, line, file_read_data):
        """format read function args."""
        read_data_pattern = re.compile(r'read\(.+,.+,.+\)')
        read_func_find = read_data_pattern.search(line)
        if read_func_find:
            read_func_str = read_func_find.group(0)
            fd = read_func_str.split(',')[0][5:]
            read_byte = read_func_str.split(',')[1][2:-1]
            if fd != '' and read_byte != ' ':
                if file_read_data.has_key(fd):
                    file_read_data[fd] = file_read_data[fd] + read_byte
                else:
                    file_read_data[fd] = read_byte

    def parse_file_read_data(self, behavior_obj):
        """parse file data from strace."""
        for line in self.strace_log:
            if 'read(' in line:
                self.format_read_str(line, behavior_obj.file_read_data)

    def parse_recvfrom_data(self, behavior_obj):
        """parse recvfrom  data ."""
        for line in self.strace_log:
            if 'recvfrom(' in line:
                self.format_recvfrom_str(line, behavior_obj.recvfrom_data)

    def parse_socket_log(self, behavior_obj):
        """parse socket related log from starce."""
        for line in self.strace_log:
            if 'connect(' in line:
                behavior_obj.socket_log['connect'].append(
                    self.parse_ip_port(line))
            if 'bind(' in line:
                behavior_obj.socket_log['bind'].append(
                    self.parse_ip_port(line))
            if 'sendto(' in line:
                behavior_obj.socket_log['sendto'].append(
                    {'port':self.parse_ip_port(line)['port'],'addr':self.parse_ip_port(line)['addr'],'info':line[line.find('sendto'):-1]})
            if 'recvfrom(' in line:
                behavior_obj.socket_log['recvfrom'].append(
                    {'port':self.parse_ip_port(line)['port'],'addr':self.parse_ip_port(line)['addr'],'info':line[line.find('recvfrom'):-1]})

    def parse_ip_port(self, log_str):
        """parse ip port from socket log."""
        connect_info = {
            'port': '',
            'addr': ''
        }
        port_pattern = re.compile(r'sin_port=htons\(\d+\)')
        addr_pattern = re.compile(r'inet_addr\(".+"\)')

        port_result = port_pattern.search(log_str)
        if port_result:
            connect_info['port'] = port_result.group(0)[15:-1]

        addr_result = addr_pattern.search(log_str)
        if addr_result:
            connect_info['addr'] = addr_result.group(0)[11:-2]
        return connect_info

    def fetch_strace_log(self, guest_vm):
        """fetch strace log from guset os."""
        if os.path.isfile(self.strace_log_path):
            os.remove(self.strace_log_path)

        self.vm_control.vm_copyfrom(
            guest_vm.name,
            guest_vm.vm_log_path,
            guest_vm.host_log_path,
            guest_vm.user, guest_vm.password
        )

    def fetch_tcpdump_log(self, guest_vm):
        """fetch tcpdump log from guest  os."""
        if os.path.isfile(self.tcpdump_log_path):
            os.remove(self.tcpdump_log_path)

        self.vm_control.vm_copyfrom(
            guest_vm.name,
            guest_vm.vm_log_tcpdump,
            guest_vm.host_log_tcpdump,
            guest_vm.user, guest_vm.password
        )

    def get_analyze_file_md5(self, filepath):
        try:
            m = hashlib.md5(open(filepath, 'rb').read())
            return m.hexdigest()

        except Exception as e:
            return ''
            logger.error("get file md5 error.", exc_info=True)

    def analyze_file(self, filepath):
        """main analyze function.  """

        self.strace_log = []
        guest_vm = VMControl.GuestVM()
        guest_vm.init_config()
        self.init_vm()

        # calculate md5
        self.md5_hash = self.get_analyze_file_md5(filepath)

        # get guest analyzer path
        file_root = os.path.dirname(__file__)
        guest_analyzer_path = os.path.join(file_root, 'GuestAnalyzer.py')
        file_name = os.path.split(filepath)[1]
        self.file_name = file_name

        if self.vm_control.start_vm(guest_vm.name) == False:
            logging.error('Start Guest VM Failed')
        self.vm_control.vm_copyto(
            guest_vm.name, filepath, guest_vm.runpath, guest_vm.user, guest_vm.password)
        self.vm_control.vm_copyto(guest_vm.name, guest_analyzer_path,
                                  guest_vm.runpath, guest_vm.user, guest_vm.password)
        self.vm_control.vm_guest_run(guest_vm.name, '/bin/chmod', ' +x %s/%s' % (
            guest_vm.runpath, file_name), guest_vm.user, guest_vm.password)

        self.vm_control.vm_guest_run(
            guest_vm.name, '/usr/bin/python',
            '%s/GuestAnalyzer.py %s/%s' % (guest_vm.guest_analyzer_path,
                                           guest_vm.guest_analyzer_path, file_name),
            guest_vm.user, guest_vm.password)

        time.sleep(10)
        self.fetch_strace_log(guest_vm)
        self.fetch_tcpdump_log(guest_vm)
        self.vm_control.control_vm(guest_vm.name, 'poweroff')
        time.sleep(5)
        self.vm_control.vm_snap_control(guest_vm.name, 'restore', 'analysis')

    def do_log_parse(self, behaviors):
        """main log parse function."""
        behaviors.md5_hash = self.md5_hash
        behaviors.file_name = self.file_name
        # parse strace log
        if os.path.isfile(self.strace_log_path):
            self.parse_strace_log(self.strace_log_path)
            os.remove(self.strace_log_path)
        self.parse_socket_log(behaviors)
        self.parse_file_log(behaviors)
        self.parse_proc_log(behaviors)
        self.parse_recvfrom_data(behaviors)
        self.parse_file_read_data(behaviors)
        # parse tcpdump info
        if os.path.isfile(self.tcpdump_log_path):
            self.parse_tcpdump_log(behaviors)
            os.remove(self.tcpdump_log_path)

    def parse_tcpdump_log(self, behaviors):
        """parse tcpdump pcap file. """
        if os.path.isfile(self.tcpdump_log_path):
            behaviors.tcp_log = self.tcp_info(self.tcpdump_log_path)
            behaviors.http_log = self.http_info(self.tcpdump_log_path)
            behaviors.udp_log = self.udp_info(self.tcpdump_log_path)
            behaviors.dns_log = self.dns_info(self.tcpdump_log_path)
            behaviors.irc_log = self.irc_info(self.tcpdump_log_path)
            behaviors.packets = self.packets_info(self.tcpdump_log_path)

    def packets_info(self, tcpdumpfile):
        cmd = [self.tshark_path, '-n', '-ta', '-r', tcpdumpfile]
        cmd_output = self.check_output_safe(cmd)
        packet_list = []
        for line in cmd_output.splitlines():
            packet_list.append(line.strip().replace('\xe2\x86\x92 ',' '))
        return packet_list

    def check_output_safe(self, cmd):
        output = ""
        try:
            output = subprocess.check_output(cmd)
        except subprocess.CalledProcessError as e:
            logging.error("CalledProcessError: %s", str(e))
            output = e.output
        return output

    def filter_packets_by_protocal(self, tcpdumpfile, protocal):
        """use tshark to analyze tcpdump pcap file"""
        if os.path.isfile(tcpdumpfile):
            cmd = [self.tshark_path, '-Tjson', '-n', '-ta', '-r', tcpdumpfile, protocal]
            cmd_output = self.check_output_safe(cmd)
            json_data = json.loads(cmd_output)

            packet_list = []
            for line in json_data:
                packet_data = {}
                if 'ip' in line['_source']['layers'].keys():
                    packet_data['ip.src'] = line['_source']['layers']['ip']['ip.src']
                    packet_data['ip.dst'] = line['_source']['layers']['ip']['ip.dst']

                if protocal == 'irc':
                    irc_info = line['_source']['layers']['irc']
                    if 'irc.response' in irc_info.keys():
                        packet_data['irc.response'] = irc_info['irc.response']

                if protocal == 'http':
                    http_info = line['_source']['layers']['http']
                    if 'http.host' in http_info.keys():
                        packet_data['http.host'] = http_info['http.host']
                    if 'http.request' in http_info.keys():
                        packet_data['http.request'] = http_info['http.request.full_uri']

                if protocal == 'dns':
                    packet_data.clear()
                    if 'dns' in line['_source']['layers'].keys():
                        dns_info = line['_source']['layers']['dns']
                        if 'Queries' in dns_info.keys():
                            for dns_query in dns_info['Queries'].values():
                                packet_data['dns_query'] = dns_query['dns.qry.name']

                packet_list.append(packet_data)

            return packet_list

    def tcp_info(self, tcpdumpfile):
        """get tcp info"""
        return self.filter_packets_by_protocal(tcpdumpfile, 'tcp')

    def udp_info(self, tcpdumpfile):
        """get udp info"""
        return self.filter_packets_by_protocal(tcpdumpfile, 'udp')

    def irc_info(self, tcpdumpfile):
        return self.filter_packets_by_protocal(tcpdumpfile, 'irc')

    def http_info(self, tcpdumpfile):
        return self.filter_packets_by_protocal(tcpdumpfile, 'http')

    def dns_info(self, tcpdumpfile):
        dns_packet = self.filter_packets_by_protocal(tcpdumpfile, 'dns')
        dns_query_list = []
        for line in dns_packet:
            if line['dns_query'] in dns_query_list:
                continue
            dns_query_list.append(line['dns_query'])
        return dns_query_list


if __name__ == '__main__':
    # test code here
    pass
