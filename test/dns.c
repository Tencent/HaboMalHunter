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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define TARGET_HOST "qq.com"
#define TARGET_PORT 22
#define HELLO_MSG "Hello world"
void error(const char *msg)
{
    perror(msg);
    exit(0);
}

int main(int argc, char *argv[])
{
    char buff[20];
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    server = gethostbyname(TARGET_HOST);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }else{
        bzero(buff,sizeof(buff));
        inet_ntop(server->h_addrtype,server->h_addr,buff,sizeof(buff)-1);
        printf("ip: %s\n",buff);
    }
    return 0;
}