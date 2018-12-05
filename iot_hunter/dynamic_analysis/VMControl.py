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
# coding=utf-8

import os
import subprocess
import logging
import time
import ConfigManager

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s - %(filename)s[line:%(lineno)d] - %(levelname)s: %(message)s')


class GuestVM:
    """Guset VM config class.

    attributes:
        name: guest name.
        user: guest os username.
        runpath: the path to run analyzing sample.
        vm_log_path: strace path in guest ost_log_path.
        guest_analyzer_path: guest analyzer script path.
        host_log_path: host os strace log path.
        host_log_tcpdump: host os tcpdump log path.
        vm_log_tcpdump: guest os tcpdump log path.

    """

    def __init__(self):
        pass

    def init_config(self):
        """ Init Guest VM from configuration file. """

        vmc = ConfigManager.ConfigManager()
        self.name = vmc.get('guest_vm', 'name')
        self.user = vmc.get('guest_vm', 'username')
        self.password = vmc.get('guest_vm', 'password')
        self.runpath = vmc.get('guest_vm', 'runpath')
        self.vm_log_path = vmc.get('guest_vm', 'vm_log_path')
        self.guest_analyzer_path = vmc.get('guest_vm', 'guest_analyzer_path')
        self.host_log_path = vmc.get('guest_vm', 'host_log_path')
        self.host_log_tcpdump = vmc.get('guest_vm', 'host_log_tcpdump')
        self.vm_log_tcpdump = vmc.get('guest_vm', 'vm_log_tcpdump')


class VMController():
    """Virtual Machine Controler.

    attributes:
        guest_vm: refer to guest vm.
        user: guest os username.
    """

    def __init__(self):

        pass

    def set_guest_vm(self, vm):
        """Set Guest VM to Control."""
        self.guest_vm = vm

    def init_config(self):
        """init virtualbox configuration."""
        config = ConfigManager.ConfigManager()
        self.vm_manage_path = config.get('vbox', 'virtualbox_path')

    def vm_cmd(self, params):
        """Execute Virtubox Manager Command. """
        vbox_cmd = '"%s\\vboxManage.exe" %s' % (self.vm_manage_path, params)
        ret = subprocess.Popen(vbox_cmd, shell=False,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = ret.stdout.read()
        logging.debug(output)
        if 'error' in output:
            logging.error('%s  Failed', vbox_cmd)
            logging.error(output)
            return False
        else:
            logging.debug('%s  Success', vbox_cmd)
            return True

    def start_vm(self, vm_name):
        """start guest vm.

        args:
                vm_name:guest vm name
        """
        #start vm in headless mode without GUI.
        vm_start_cmd = 'startvm %s --type headless' % vm_name
        return self.vm_cmd(vm_start_cmd)

    def control_vm(self, vm_name, params):
        """Control Guest VM."""
        vm_control_cmd = 'controlvm %s %s' % (vm_name, params)
        return self.vm_cmd(vm_control_cmd)

    def vm_guest_run(self, vm_name, exe, params, username, password):
        """run process in guest os.

        args:
                vm_name: guest os name.
                exe: executable file to run in guest os.
                params: params with file to run.
                username: guest os user name.
                password: guest os passwd.
        """
        vm_run_cmd = 'guestcontrol %s run "%s" %s --username %s --password %s  --verbose' % (
            vm_name, exe, params, username, password)
        return self.vm_cmd(vm_run_cmd)

    def vm_copyto(self, vm_name, src, dst, username, password):
        """Copy file from host to guest vm."""
        vm_copyto_cmd = 'guestcontrol %s copyto  --target-directory %s %s --username %s --password %s  --verbose' % (
            vm_name, dst, src, username, password)
        return self.vm_cmd(vm_copyto_cmd)

    def vm_copyfrom(self, vm_name, src, dst, username, password):
        """Copy file from guest os to host os."""
        vm_copyfrom_cmd = 'guestcontrol %s copyfrom --target-directory %s %s --username %s --password %s  --verbose' % (
            vm_name, dst, src, username, password)
        return self.vm_cmd(vm_copyfrom_cmd)

    def vm_snap_control(self, vm_name, cmd, sanp_name):
        """ VM Snapshot control. """
        vm_snap_cmd = 'snapshot %s %s %s' % (vm_name, cmd, sanp_name)
        return self.vm_cmd(vm_snap_cmd)


if __name__ == '__main__':
    vm_control = VMController()
    vm_control.init_config()
    guest_vm = GuestVM()
    guest_vm.init_config()
    vm_control.set_guest_vm(guest_vm)
    vm_control.start_vm(vm_control.guest_vm.vm_name)
