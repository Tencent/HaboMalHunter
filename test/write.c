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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>


#define CTX "Hello World"

int main(){
        int fd = open("test.txt", O_TRUNC| O_CREAT| O_RDWR, S_IRUSR|S_IWUSR);
        if (-1 == fd){
                perror("[open]");
                exit(1);
        }
        int ret = write(fd,CTX,strlen(CTX));
        if (-1==ret){
                perror("[write]");
                exit(2);
        }
        close(fd);
        return 0;
}
