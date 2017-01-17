# coding:utf-8

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
import base64
from pyh import *


DICTIONARY_CONFIG = 'i18n.csv'
cn2enDict = {}

def ChangeELFLog2Html(sample_dir): 
    static_file  = "%s/%s.static" % (sample_dir,"output")
    dynamic_file = "%s/%s.xpcn" % (sample_dir,"output")
    html_file    = "%s/%s.html" % (sample_dir,"output")

    if os.path.isfile(static_file) :
        fStatic     = open(static_file, "r")
        staticJson  = json.loads(fStatic.read())
        fStatic.close()

    if os.path.isfile(dynamic_file):
        fDynamic    = open(dynamic_file, "r")
        dynamicJson = json.loads(fDynamic.read())
        fDynamic.close()

    if os.path.isfile(DICTIONARY_CONFIG):
        fDict = open(DICTIONARY_CONFIG, 'r')

        for line in fDict.readlines():
            item = line.split(',', 1)
            if len(item) == 2:
                key = item[0].decode('utf-8')
                cn2enDict[key] = item[1]

        fDict.close()



    page = PyH('Habo Analysis System')

    page.addStyleSnippet('head.css')
    page.addStyleSnippet('font-awesome.min.css')
    page.addStyleSnippet('common.css')
    page.addStyleSnippet('index.css')
    page.addStyleSnippet('detail.css')

    page << link(type="text/css", rel="stylesheet", href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css")

    page << script('function f_show_sub_base(obj){\
                    $(obj).hide(); \
                    $("#subinfo").show();\
                    }\
                  ')

    #myImg = img(width='15', height='15', src='data:image/png;base64,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')


    myDivWrapper = div(cl='wrapper') 

    myDivContainer = div(cl='container extra-info', style='padding:10px 0') 

    myDivContainer << div(cl='clearfix') \
                   << div(cl='margin-top-2') \
                   << a()  \
                   << img( alt='VirusTotal', src='data:image/png;base64,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') 



    myDetailFrame = div(id='detail_frame')


    #BaseInfo
    myEnumContainer = div(cl='enum-container')

    myDivFrame = div(cl='frame', style='margin:20px 0') 
    myDivFrame << div(id='basic-info') \
               << div(cl='row') \
               << div(cl='span8 columns') 
    myTable = table(style='margin-bottom:8px;margin-left:8px;') 
    myTable << tbody()


    md5hash  = None
    filetype = None
    copyright = None
    productversion = None
    compiler = None

    if staticJson.has_key('BaseInfo'):

        if staticJson['BaseInfo'][0].has_key('MD5'):
            md5hash = staticJson['BaseInfo'][0]['MD5']

    if staticJson.has_key('BaseInfo'):

        if staticJson['BaseInfo'][0].has_key('FileType'):
            filetype = staticJson['BaseInfo'][0]['FileType']


    myTable << tr() \
                << td('MD5:') \
                << td('%s' % md5hash)

    myTable << tr() \
                << td('File type:') \
                << td('%s' % filetype)



    if staticJson.has_key('SubBaseInfo'):

        myTable <<  tr() 
        myTable << td('Sub-file information:', nowrap='nowrap', style='vertical-align:top') 


        myWordWrap  = td(style='word-wrap:break-word;word-break:break-all') 
        myWordWrap  << a('Detail', id='moreinfo', onclick='f_show_sub_base(this)', style='cursor:pointer')
        
            
        myTbody = tbody()

        for item in staticJson['SubBaseInfo']:

            subName = os.path.basename(item['Name'])
            subType = item['FileType']
            subMd5  = item['MD5']

            myEven  = tr(cl='even')
            myEven  << td('%s&nbsp;/&nbsp;%s&nbsp;/&nbsp;%s' % (subName, subMd5, subType))
 
            myTbody << myEven

        myWordWrap  << div(id='subinfo', style='display:none') \
                    << table(cl='dtable') \
                    << myTbody

        myTable << myWordWrap


    myEnumContainer << myDivFrame << myTable
    myDetailFrame << myEnumContainer


    #Dynamic Info------------------------------------

    if dynamicJson.has_key('Dynamic'):
        dynamicJson = dynamicJson['Dynamic']

    #Key behaviour
    if dynamicJson.has_key('KeyInfo') and len(dynamicJson['KeyInfo']) > 0:

        myDetailFrame << h5('Key behaviour') 
        myEnumContainer = div(cl='enum-container')
        myTable = table(cl='red dtable') 
        myTable << tbody()

        for key in dynamicJson['KeyInfo']:

            if key in cn2enDict:
                key_en = cn2enDict[key]
            else:
                key_en = key

            myTable << tr() \
                    << td('Behaviour:', cl='tdtitle') \
                    << td('%s' % key_en)

            myTd  =  td(style='word-wrap:break-word;word-break:break-all') 

            for item in dynamicJson['KeyInfo'][key]:

                myTd << p('%s' % item, title='%s' % item)

            myTable << tr() \
                    << td('Detail info:', width='1%', nowrap='nowrap', style='vertical-align:top') \
                    << myTd


        myEnumContainer  << myTable
        myDetailFrame << myEnumContainer

    #Process
    if dynamicJson.has_key('Process') and len(dynamicJson['Process']) > 0:

        myDetailFrame << h5('Process') 
        myEnumContainer = div(cl='enum-container')
        myTable = table(cl='dtable') 
        myTable << tbody()

        for key in dynamicJson['Process']:

            if key in cn2enDict:
                key_en = cn2enDict[key]
            else:
                key_en = key

            myTable << tr() \
                    << td('Behaviour:', cl='tdtitle') \
                    << td('%s' % key_en)

            myTd  =  td(style='word-wrap:break-word;word-break:break-all') 

            for item in dynamicJson['Process'][key]:

                myTd << p('%s' % item, title='%s' % item)

            myTable << tr() \
                    << td('Detail info:', width='1%', nowrap='nowrap', style='vertical-align:top') \
                    << myTd


        myEnumContainer  << myTable
        myDetailFrame << myEnumContainer



    #File
    if dynamicJson.has_key('File') and len(dynamicJson['File']) > 0:

        myDetailFrame << h5('File') 
        myEnumContainer = div(cl='enum-container')
        myTable = table(cl='dtable') 
        myTable << tbody()

        for key in dynamicJson['File']:

            if key in cn2enDict:
                key_en = cn2enDict[key]
            else:
                key_en = key

            myTable << tr() \
                    << td('Behaviour:', cl='tdtitle') \
                    << td('%s' % key_en)

            myTd  =  td(style='word-wrap:break-word;word-break:break-all') 

            for item in dynamicJson['File'][key]:

                myTd << p('%s' % item, title='%s' % item)

            myTable << tr() \
                    << td('Detail info:', width='1%', nowrap='nowrap', style='vertical-align:top') \
                    << myTd

        myEnumContainer  << myTable
        myDetailFrame << myEnumContainer


    #Network
    if dynamicJson.has_key('Net') and len(dynamicJson['Net']) > 0:

        myDetailFrame << h5('Network') 
        myEnumContainer = div(cl='enum-container')
        myTable = table(cl='dtable') 
        myTable << tbody()

        for key in dynamicJson['Net']:

            if key in cn2enDict:
                key_en = cn2enDict[key]
            else:
                key_en = key

            myTable << tr() \
                    << td('Behaviour:', cl='tdtitle') \
                    << td('%s' % key_en)

            myTd  =  td(style='word-wrap:break-word;word-break:break-all') 

            for item in dynamicJson['Net'][key]:

                myTd << p('%s' % item, title='%s' % item)

            myTable << tr() \
                    << td('Detail info:', width='1%', nowrap='nowrap', style='vertical-align:top') \
                    << myTd

        myEnumContainer  << myTable
        myDetailFrame << myEnumContainer

    #Registry
    if dynamicJson.has_key('Reg') and len(dynamicJson['Reg']) > 0:

        myDetailFrame << h5('Registry') 
        myEnumContainer = div(cl='enum-container')
        myTable = table(cl='dtable') 
        myTable << tbody()

        for key in dynamicJson['Reg']:

            if key in cn2enDict:
                key_en = cn2enDict[key]
            else:
                key_en = key

            myTable << tr() \
                    << td('Behaviour:', cl='tdtitle') \
                    << td('%s' % key_en)

            myTd  =  td(style='word-wrap:break-word;word-break:break-all') 

            for item in dynamicJson['Reg'][key]:

                myTd << p('%s' % item, title='%s' % item)

            myTable << tr() \
                    << td('Detail info:', width='1%', nowrap='nowrap', style='vertical-align:top') \
                    << myTd

        myEnumContainer  << myTable
        myDetailFrame << myEnumContainer

    #Hook
    if dynamicJson.has_key('Hook') and len(dynamicJson['Hook']) > 0:

        myDetailFrame << h5('Hook') 
        myEnumContainer = div(cl='enum-container')
        myTable = table(cl='dtable') 
        myTable << tbody()

        for key in dynamicJson['Hook']:

            if key in cn2enDict:
                key_en = cn2enDict[key]
            else:
                key_en = key

            myTable << tr() \
                    << td('Behaviour:', cl='tdtitle') \
                    << td('%s' % key_en)

            myTd  =  td(style='word-wrap:break-word;word-break:break-all') 

            for item in dynamicJson['Hook'][key]:

                myTd << p('%s' % item, title='%s' % item)

            myTable << tr() \
                    << td('Detail info:', width='1%', nowrap='nowrap', style='vertical-align:top') \
                    << myTd

        myEnumContainer  << myTable
        myDetailFrame << myEnumContainer

    #Other
    if dynamicJson.has_key('Other') and len(dynamicJson['Other']) > 0:

        myDetailFrame << h5('Other') 
        myEnumContainer = div(cl='enum-container')
        myTable = table(cl='dtable') 
        myTable << tbody()

        for key in dynamicJson['Other']:

            if key in cn2enDict:
                key_en = cn2enDict[key]
            else:
                key_en = key

            myTable << tr() \
                    << td('Behaviour:', cl='tdtitle') \
                    << td('%s' % key_en)

            myTd  =  td(style='word-wrap:break-word;word-break:break-all') 

            for item in dynamicJson['Other'][key]:

                myTd << p('%s' % item, title='%s' % item)

            myTable << tr() \
                    << td('Detail info:', width='1%', nowrap='nowrap', style='vertical-align:top') \
                    << myTd

        myEnumContainer  << myTable
        myDetailFrame << myEnumContainer

    myDivWrapper << myDivContainer << myDetailFrame
    myDivWrapper << div(cl='push')
    page << myDivWrapper

    page << div(cl='footer center') << div(u'Copyright © 1998 - 2016 Tencent.All Rights Reserved', style='width: 1000px; margin: 0 auto')

    page.printOut(html_file)



if __name__=="__main__":

    # arg1 = sample log directory
    # arg2 = log type(apk/pe)

    if sys.argv[2] == '-elf':
        ChangeELFLog2Html(sys.argv[1])