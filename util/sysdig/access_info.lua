--[[

Tencent is pleased to support the open source community by making HaboMalHunter available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in 
compliance with the License. You may obtain a copy of the License at

http://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software distributed under the 
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. See the License for the specific language governing permissions 
and limitations under the License.

Author: 
Date:	August 22, 2016
Description: Linux Malware Analysis System : Sysdig plugins : file read write
--]]

description = "Show the info about read write syscall"
short_description = "read and write info"
category = "malware"

args = {
	{
		name = "pname",
		description = 'proc.name',
		argtype = 'string',
		optional = false
	},
	{
		name = "pid",
		description = 'the pid of the process',
		argtype = 'int',
		optional = false
	},
	{
		name = "rw_type",
		description = 'type of the operation(read|write)',
		argtype = "string",
		optional = false
	},
}

-- Argument notification callback
function on_set_arg(name, val)
	if name == "pname" then
		g_pname = val
	end
	if name == "pid" then
	   g_pid = val
	end
	if name == "rw_type" then
		rw_type = val
	end
	return true
end

-- Initialization callback
function on_init()
	-- print("pid %d",g_pid)
	-- watching terminals risks looping in a live capture , copy from spy_file.lua
	local filter = "(not fd.name contains /dev/pt and not fd.name contains /dev/tty) and "
	filter = string.format("%s fd.type=file and evt.dir=< and (proc.pid >= %d or proc.apid = %d or proc.name contains %s ) and", filter, g_pid, g_pid, g_pname)
	if rw_type == "read" then
		filter = string.format("%s evt.is_io_read=true", filter)
	else
		filter = string.format("%s evt.is_io_write=true", filter)
	end
	-- print(filter)
	chisel.set_filter(filter)

	-- Request the fields
	fevtime = chisel.request_field("evt.time")
	fevtype = chisel.request_field("evt.type")
	fexeline = chisel.request_field("proc.exeline")
	fsrc_pid = chisel.request_field("proc.pid") --int
	fpname = chisel.request_field("proc.name")
	fsrc_tid = chisel.request_field("thread.tid") --int
	fraw_arg_exe = chisel.request_field("evt.rawarg.exe")
	fraw_arg_res = chisel.request_field("evt.rawres")
	ffdname = chisel.request_field("fd.name")
	-- fdata = chisel.request_field("evt.arg.data")
	fdata = chisel.request_field("evt.buffer")
	-- set buffer as 4k
	sysdig.set_snaplen(4096)
	-- TODO format 
	-- sysdig.set_output_format("ascii")
	sysdig.set_output_format("normal")
	return true
end

json = require ("dkjson")
-- Event parsing callback
function on_event()
	-- The fork syscall will return twice
	local dir = evt.field(fevt_dir)
	local ts = ""
	local src = ""
	local dst = ""
	local line = ""
	local path = evt.field(ffdname)

	exeline = evt.field(fexeline)
	-- exclude inetsim, strace, AnalyzeControl, vbox and ltrace
	if string.find(exeline,"inetsim") or string.find(exeline,"ltrace") or string.find(exeline,"strace") or string.find(exeline,"kill") or string.find(string.lower(exeline),"vbox") or string.find(exeline, "AnalyzeControl") then
		return true
	end
	-- exclude the log file for LD_DEBUG
	if string.find(path, "ld_debug.log") then
		return true
	end
	ts =  evt.field(fevtime)
	src = string.format("%s(PID=%d, TID=%d)", evt.field(fexeline), evt.field(fsrc_pid), evt.field(fsrc_tid))
	dst = string.format("%s: path=%s, size=%d",evt.field(fevtype), path, evt.field(fraw_arg_res))
	buffer = evt.field(fdata)
	buffer = json.encode(buffer)
	line = string.format('["%s", "%s", "%s" , %s]', ts, src, dst, buffer)
	print(line)

	return true
end	
