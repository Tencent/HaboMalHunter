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
Description: Linux Malware Analysis System : Sysdig plugins
--]]

description = "Show the info about socket syscall"
short_description = "socket info"
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
}

-- Argument notification callback
function on_set_arg(name, val)
	if name == "pname" then
		g_pname = val
	end
	if name == "pid" then
	   g_pid = val
	end
	return true
end

-- Initialization callback
function on_init()
	-- print("pid %d",g_pid)
	local filter = string.format(" evt.type=connect and evt.dir=< and (proc.pid >= %d or proc.apid = %d or proc.name contains %s)", g_pid, g_pid, g_pname)
	-- print(filter)
	chisel.set_filter(filter)
	-- Request the fields
	fevtime = chisel.request_field("evt.time")
	fevtype = chisel.request_field("evt.type")
	fexeline = chisel.request_field("proc.exeline")
	fsrc_pid = chisel.request_field("proc.pid") --int
	fsrc_tid = chisel.request_field("thread.tid") --int

	fevtinfo = chisel.request_field("evt.info")
	fevt_tuple=chisel.request_field("evt.arg.tuple")
	return true
end

proc_name={}
-- Event parsing callback
function on_event()
	local ts = ""
	local src = ""
	local dst = ""
	local line = ""
	exeline = evt.field(fexeline)
	-- exclude inetsim, strace, AnalyzeControl, vbox and ltrace
	if string.find(exeline,"inetsim") or string.find(exeline,"ltrace") or string.find(exeline,"strace") or string.find(exeline,"kill") or string.find(string.lower(exeline),"vbox") or string.find(exeline, "AnalyzeControl") then
		return true
	end
	ts =  evt.field(fevtime)
	src = string.format("%s(PID=%d, TID=%d)",evt.field(fexeline), evt.field(fsrc_pid), evt.field(fsrc_tid))
	dst = string.format("%s: %s", evt.field(fevtype),evt.field(fevt_tuple))
	line = string.format('["%s", "%s", "%s" ]', ts, src, dst)
	print(line)
	return true
end	
