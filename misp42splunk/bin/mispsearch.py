#!/usr/bin/env python
# coding=utf-8
#
# search for value in MISP and add some fields to the pipeline
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#

import os
import sys
import ConfigParser
import requests
import json
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import logging

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"

@Configuration(local=True)

class MispSearchCommand(StreamingCommand):
    """ search in MISP for attributes matching the value of field.

    ##Syntax

        code-block::
        mispsearch field=<field> onlyids=y|n

    ##Description

        body = {"returnFormat": "json",
                "value": "optional",
                "type": "optional",
                "category": "optional",
                "org": "optional",
                "tags": "optional",
                "from": "optional",
                "to": "optional",
                "last": "optional",
                "eventid": "optional",
                "withAttachments": "optional",
                "uuid": "optional",
                "publish_timestamp": "optional",
                "timestamp": "optional",
                "enforceWarninglist": "optional",
                "to_ids": "optional",
                "deleted": "optional",
                "includeEventUuid": "optional",
                "event_timestamp": "optional",
                "threat_level_id": "optional"
                }
    
    ##Example

    Search in MISP for value of fieldname r_ip (remote IP in proxy logs).

        code-block::
         * | mispsearch fieldname=r_ip

    """

    field = Option(
        doc='''
        **Syntax:** **field=***<fieldname>*
        **Description:**Name of the field containing the value to search for.''',
        require=True, validate=validators.Fieldname())

    onlyids = Option(
        doc='''
        **Syntax:** **onlyids=***<y|n>*
        **Description:** Boolean to search only attributes with to_ids set''',
        require=False, validate=validators.Match("onlyids", r"^[yYnN01]+$"))

    gettag = Option(
        doc='''
        **Syntax:** **gettag=***<y|n>*
        **Description:** Boolean to return attribute tags''',
        require=False, validate=validators.Match("gettag", r"^[yYnN01]+$"))

# Superseede MISP instance for this search
    misp_url = Option(
        doc='''
        **Syntax:** **misp_url=***<MISP URL>*
        **Description:**URL of MISP instance.''',
        require=False, validate=validators.Match("misp_url", r"^https?:\/\/[0-9a-zA-Z\-\.]+(?:\:\d+)?$"))

    misp_key = Option(
        doc='''
        **Syntax:** **misp_key=***<AUTH_KEY>*
        **Description:**MISP API AUTH KEY.''',
        require=False, validate=validators.Match("misp_key", r"^[0-9a-zA-Z]{40}$"))

    misp_verifycert = Option(
        doc = '''
        **Syntax:** **misp_verifycert=***<y|n>*
        **Description:**Verify or not MISP certificate.''',
        require=False, validate=validators.Match("misp_verifycert", r"^[yYnN01]$"))


    def stream(self, records):
        # self.logger.debug('mispgetioc.reduce')
        _SPLUNK_PATH = os.environ['SPLUNK_HOME']

        # open misp.conf
        config_file = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'local' + os.sep + 'misp.conf'
        mispconf = ConfigParser.RawConfigParser()
        mispconf.read(config_file)

        # Generate args
        my_args = {}
        # MISP instance parameters
        if self.misp_url:
            my_args['misp_url'] = self.misp_url + '/attributes/restSearch'
            logging.debug('misp_url as option, value is %s', my_args['misp_url'])
        else:
            my_args['misp_url'] = mispconf.get('mispsetup', 'misp_url') + '/attributes/restSearch'
            logging.debug('misp.conf: misp_url value is %s', my_args['misp_url'])
        if self.misp_key:
            my_args['misp_key'] = self.misp_key
            logging.debug('misp_key as option, value is %s', my_args['misp_key'])
        else:
            my_args['misp_key'] = mispconf.get('mispsetup', 'misp_key')
            logging.debug('misp.conf: misp_key value is %s', my_args['misp_key'])
        if self.misp_verifycert:
            if self.misp_verifycert == 'Y' or self.misp_verifycert == 'y' or self.misp_verifycert == '1':
                my_args['misp_verifycert'] = True
            else:
                my_args['misp_verifycert'] = False
            logging.debug('misp_verifycert as option, value is %s', my_args['misp_verifycert'])
        else:
            if mispconf.has_option('mispsetup', 'misp_verifycert'):
                my_args['misp_verifycert'] = mispconf.getboolean('mispsetup', 'misp_verifycert')
                logging.debug('misp.conf: misp_verifycert value is %s', my_args['misp_verifycert'])
            else:
                my_args['misp_verifycert'] = True
                logging.debug('misp.conf: misp_verifycert value not set. Default to True')

        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['misp_key']
        headers['Accept'] = 'application/json'

        fieldname = str(self.field)
        if self.onlyids == 'Y' or self.onlyids == 'y' or self.onlyids == '1':
            to_ids = True
        else:
            to_ids = False
        if self.gettag == 'Y' or self.gettag == 'y' or self.gettag == '1':
            get_tag = True
        else:
            get_tag = False

        for record in records:
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    body_dict = { "returnFormat": "json"}
                    body_dict['value'] = str(value)
                    body_dict['withAttachments'] = "false",
                    if to_ids:
                        body_dict['to_ids'] = "True"
                    
                    body = json.dumps(body_dict)
                    misp_category = ''
                    misp_event_id = ''
                    misp_to_ids = ''
                    misp_tag = ''
                    misp_type = ''
                    misp_value = ''
                    misp_uuid = ''
                    delimns = ''
                    tag_delimns = ''
                    # search 
                    r = requests.post(my_args['misp_url'], headers=headers, data=body, verify=my_args['misp_verifycert'])
                    # check if status is anything other than 200; throw an exception if it is
                    r.raise_for_status()
                    # response is 200 by this point or we would have thrown an exception
                    # print >> sys.stderr, "DEBUG MISP REST API response: %s" % response.json()
                    response = r.json()
                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            record['misp_json'] = response['response']['Attribute']
                            for a in response['response']['Attribute']:
                                misp_type = misp_type + delimns + str(a['type'])
                                misp_value = misp_value + delimns + str(a['value'])
                                misp_to_ids = misp_to_ids + delimns + str(a['to_ids'])
                                misp_category = misp_category + delimns + str(a['category'])
                                misp_uuid = misp_uuid + delimns + str(a['uuid'])
                                misp_event_id = misp_event_id + delimns + str(a['event_id'])
                                if get_tag and 'Tag' in a:
                                    for tag in a['Tag']:
                                        misp_tag = misp_tag + tag_delimns + str(tag['name'])
                                        tag_delimns = ','
                                delimns = ','
                            record['misp_type'] = misp_type
                            record['misp_value'] = misp_value
                            record['misp_to_ids'] = misp_to_ids
                            record['misp_category'] = misp_category
                            record['misp_uuid'] = misp_uuid
                            record['misp_event_id'] = misp_event_id
                            if get_tag:
                                record['misp_tag'] = misp_tag

            yield record

if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)
    dispatch(MispSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)