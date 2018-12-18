#!/usr/bin/env python
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

import sys
import os
import argparse
import json
from conf import *
from common import *
try:
    from elasticsearch import Elasticsearch
    from elasticsearch import helpers
except ImportError as e:
    raise ImportError("\nImport faild: %s.\n"  % str(e) \
                      + "elasticsearch package not installed.\n" \
                      + "see https://github.com/elastic/elasticsearch-py")

defaultencoding = 'utf-8'
if sys.getdefaultencoding() != defaultencoding:
    reload(sys)
    sys.setdefaultencoding(defaultencoding)

class ElasticSearchUtil():
    """
    official docs : https://elasticsearch-py.readthedocs.io/
    """
    
    def __init__(self, host = None):
        self.conn = Elasticsearch(host)
        self.file_lines = 0
    
    def __del__(self):
        if not self.conn:
            self.conn.close()
            self.file_lines = 0
    
    def create(self, index):
        return self.conn.indices.create(index, ignore = 400)
    
    def insert(self, index, doc_type, body, id = None):
        return self.conn.index(index, doc_type, body, id)
    
    def delete_all(self, index, doc_type = None):
        return self.conn.indices.delete(index)
    
    def delete_by_id(self, index, doc_type, id):
        return self.conn.delete(index, doc_type, id = id)
        
    def delete_by_query(self, index, body, doc_type = None):
        return self.conn.delete_by_query(index, body, doc_type)
    
    def update(self, index, doc_type, body, id):
        return self.conn.update(index, doc_type, body, id)
    
    def search(self, index = None, doc_type = None, body = None):
        return self.conn.search(index, doc_type, body)
    
    def get(self, index, doc_type, id):
        return self.conn.get(index, doc_type, id)
    
    def bulk(self, action):
        return helpers.bulk(self.conn, action)
    
    def get_file_data(self, index, doc_type, file_path):
        with open(file_path, 'rb') as f:
            for result in f:
                self.file_lines += 1
                try:
                    res_json = json.loads(result)
                    yield {
                            "_index": index,
                            "_type": doc_type,
                            "_id": res_json["md5"],
                            "_source": result
                        }
                except Exception as e:
                    logger.error("get_file_data():Load json error.%s" % result, exc_info=True)
        
    def bulk_by_file(self, index, doc_type, file_path):
        self.file_lines = 0
        if not os.path.isfile(file_path):
            logger.error("bulk_by_file():Invalid File Path: %s" % file_path)
            return 
        
        logger.info("Import data from file:%s" % file_path)
        
        ret = self.bulk(self.get_file_data(index, doc_type, file_path))
        success = ret[0]
        fail = self.file_lines - success
        logger.info("Import data complete.Success:%d Fail:%d" % (success, fail))

def main():
    parser = argparse.ArgumentParser(description = 'Import Data Tool for Elasticsearch.')
    parser.add_argument('-r', dest='result_file_path', default=None, help='load analysis result info to elasticsearch')
    parser.add_argument('-o', dest='output_dir', default=None, help='output folder path for log files,use RESULT_OUTPUT_DIR as default in conf.py.')
    args = parser.parse_args()
    
    while True:
        output_dir = RESULT_OUTPUT_DIR
        if args.output_dir:
            output_dir = os.path.abspath(args.output_dir)
        
        if not os.path.isdir(output_dir):
            print ("Invalid Path: %s" % output_dir)
            print ("ERROR: You need to set RESULT_OUTPUT_DIR in file conf.py or use -o to set this variable.")
            break
        
        global logger
        logger = enable_logging(ES_LOGGER_NAME, os.path.join(output_dir, ES_IMPORT_DATA_LOG))
        
        if not args.result_file_path:
            parser.print_help()
            break 
        else:
            es = ElasticSearchUtil(ES_HOST)
            es.bulk_by_file(ES_INDEX_NAME, ES_TYPE_NAME, args.result_file_path)
        
        break
        
if __name__ == '__main__':
    main()
