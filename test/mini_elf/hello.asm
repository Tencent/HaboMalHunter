; Tencent is pleased to support the open source community by making HaboMalHunter available.
; Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
; Licensed under the MIT License (the "License"); you may not use this file except in 
; compliance with the License. You may obtain a copy of the License at
; 
; http://opensource.org/licenses/MIT
; 
; Unless required by applicable law or agreed to in writing, software distributed under the 
; License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
; either express or implied. See the License for the specific language governing permissions 
; and limitations under the License.

; assemble: nasm -f elf hello.asm
; link: gcc -o hello hello.o
; run: ./hello
; %rax=1 ; sys_write
; %rdi=1 unsigned int fd
; %rsi= const char *buf
; %rdx= size_t count

; %rax=60 ; sys_exit
; %rdi=0 ; int error_code

	SECTION .rodata
buffer: times 20000 db 0xff
	SECTION .data
msg:	db "Hello World",10
len:	equ $-msg

	SECTION .text
	global _start
_start:
	mov rdx, len
	mov rsi, msg
	mov rdi, 1
	mov rax, 1
	syscall	; write(1,msg,len)
	mov rdi,0
	mov rax,60 	; exit(0)
	syscall


