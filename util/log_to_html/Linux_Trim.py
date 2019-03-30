#!/usr/bin/python
#encoding: utf-8
#Version 1.0.0.1

"""
Tencent is pleased to support the open source community by making HaboMalHunter available.
Copyright (C) 2017 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in 
compliance with the License. You may obtain a copy of the License at

http://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software distributed under the 
License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
either express or implied. See the License for the specific language governing permissions 
and limitations under the License.
"""
import os 
import sys
import json

def classifyLogInfo(dynamicLog):

    infoDict = {}
    infoDict["Dynamic"] = {"Process":{}, "File":{}, "Net":{}, "Other":{}}

    xpcn = "%s/output.xpcn" % os.path.dirname(dynamicLog)


    if os.path.exists(dynamicLog):
        f = open(dynamicLog, "r")
        dyContent = f.read()
        f.close()

        dyJson = json.loads(dyContent)

        for item in dyJson:
            try:
                detail = item[2]
                dyID = int(item[3])
                desript = item[4]

                if dyID in (8020005, 8020006, 8020007, 8020008, 8020009, 8020010, 8020011, 8020012):
                    if infoDict["Dynamic"]["Process"].has_key(desript):
                        infoDict["Dynamic"]["Process"][desript].append(detail)
                    else:
                        infoDict["Dynamic"]["Process"][desript] = [detail]

                elif dyID in (8020201, 8020202, 8020203, 8020204, 8020205, 8020206, 8020210, 8020212):

                    if infoDict["Dynamic"]["File"].has_key(desript):
                        infoDict["Dynamic"]["File"][desript].append(detail)
                    else:
                        infoDict["Dynamic"]["File"][desript] = [detail]

                elif dyID in (8020401, 8020402, 8020403, 8020404, 8020405, 8020406, 8020407, 8020408, 8020409, 8020410, 8020414):

                    if infoDict["Dynamic"]["Net"].has_key(desript):
                        infoDict["Dynamic"]["Net"][desript].append(detail)
                    else:
                        infoDict["Dynamic"]["Net"][desript] = [detail]
                elif dyID in (8020603, 8020604, 8020605):

                    if infoDict["Dynamic"]["Other"].has_key(desript):
                        infoDict["Dynamic"]["Other"][desript].append(detail)
                    else:
                        infoDict["Dynamic"]["Other"][desript] = [detail]
            except Exception as e:
                pass

        for key in infoDict["Dynamic"]["Process"]:

            infoDict["Dynamic"]["Process"][key] = list(set(infoDict["Dynamic"]["Process"][key]))[0:15]

        for key in infoDict["Dynamic"]["File"]:

            infoDict["Dynamic"]["File"][key] = list(set(infoDict["Dynamic"]["File"][key]))[0:15]

        for key in infoDict["Dynamic"]["Net"]:

            infoDict["Dynamic"]["Net"][key] = list(set(infoDict["Dynamic"]["Net"][key]))[0:15]

        for key in infoDict["Dynamic"]["Other"]:

            infoDict["Dynamic"]["Other"][key] = list(set(infoDict["Dynamic"]["Other"][key]))[0:15]
            

        fXpcn = open(xpcn, "w")
        fXpcn.write(json.dumps(infoDict))
        fXpcn.close()



if __name__ == "__main__":

    classifyLogInfo(sys.argv[1])
