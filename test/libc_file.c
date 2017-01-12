// Tencent is pleased to support the open source community by making HaboMalHunter available.
// Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
// Licensed under the MIT License (the "License"); you may not use this file except in 
// compliance with the License. You may obtain a copy of the License at
// 
// http://opensource.org/licenses/MIT
// 
// Unless required by applicable law or agreed to in writing, software distributed under the 
// License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
// either express or implied. See the License for the specific language governing permissions 
// and limitations under the License.

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define CTX "HELLO"

void create_file(const char* fname){
	int fd = open(fname,"wb");
	if (-1!=fd){
		write(fd,CTX,strlen(CTX));
		close(fd);
	}
	printf("create %s\n",fname);
}

void rename_file(const char* fsrc, const char* fdest){
	int ret = rename(fsrc, fdest);
	printf("rename file %s -> %s, ret:%d", fsrc, fdest, ret);
}

void remove_file(const char* fname){
	int ret = remove(fname);
	printf("remove file %s\n",fname);
}
int main(){
	create_file("a.txt");
	rename_file("a.txt","b.txt");
	remove_file("b.txt");
	return 0;
}