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
#include <sys/types.h>
#include <sys/wait.h>

#define LEN 100
char buff[LEN];
int main(int argc, char ** argv){
        printf("starts\n");
        int lev=0;
        while (lev<10){
                snprintf(buff,LEN-1,"lev_%d",lev);
                pid_t pid = fork();
                if (0==pid){ // child
                        argv[0]=buff;
                        printf("I am in %s, current:%d\n",buff,getpid());
                }else if (pid>0){ //parent
                        int status=0;
                        pid_t ret_pid = wait(&status);
                        printf("child: %d, wait got %d, current: %d\n",pid,ret_pid,getpid());
                        break;
                }else{
                        printf("fork failed\n");
                }
                lev++;
        }
        printf("end\n");
}
