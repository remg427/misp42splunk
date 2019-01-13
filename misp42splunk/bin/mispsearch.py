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

import sys
import requests
import json
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunk.clilib import cli_common as cli
import logging

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "2.0.14"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def prepare_config(self):
    # Generate confg_args
    config_args = {}
    # open misp.conf
    mispconf = cli.getConfStanza('misp','mispsetup')        
    # MISP instance parameters
    # get specific misp url and key if any (and misp_verifycert)
    if self.misp_url and self.misp_key:
        config_args['misp_url'] = self.misp_url
        logging.info('misp_url as option, value is %s', config_args['misp_url'])
        config_args['misp_key'] = self.misp_key
        logging.info('misp_key as option, value is %s', config_args['misp_key'])
        if self.misp_verifycert:
            config_args['misp_verifycert'] = self.misp_verifycert
        else:
            config_args['misp_verifycert'] = False
        logging.info('misp_verifycert as option, value is %s', config_args['misp_verifycert'])
    else:
        # get MISP settings stored in misp.conf
        config_args['misp_url'] = mispconf.get('misp_url')
        logging.info('misp.conf: misp_url value is %s', config_args['misp_url'])
        config_args['misp_key'] = mispconf.get('misp_key')
        logging.info('misp.conf: misp_key value is %s', config_args['misp_key'])
        if int(mispconf.get('misp_verifycert')) == 1:
            config_args['misp_verifycert'] = True
        else:
            config_args['misp_verifycert'] = False
        logging.info('misp.conf: misp_verifycert value is %s', config_args['misp_verifycert'])
    # get proxy parameters if any
    http_proxy = mispconf.get('http_proxy', '')
    https_proxy = mispconf.get('https_proxy', '')
    if http_proxy != '' and https_proxy != '':
        config_args['proxies'] = {
            "http": http_proxy,
            "https": https_proxy
        }
    else:
        config_args['proxies'] = {}
    logging.info('proxies dict is %s', json.dumps(config_args['proxies']))

    return config_args


@Configuration(distributed=False)
class MispSearchCommand(StreamingCommand):
    """ search in MISP for attributes matching the value of field.

    ##Syntax

        code-block::
        mispsearch field=<field> onlyids=y|n

    ##Description

        body =  {
                    "returnFormat": "mandatory",
                    "page": "optional",
                    "limit": "optional",
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
                    "includeEventTags": "optional",
                    "event_timestamp": "optional",
                    "threat_level_id": "optional",
                    "eventinfo": "optional"
                }
    
    ##Example

    Search in MISP for value of fieldname r_ip (remote IP in proxy logs).

        code-block::
         * | mispsearch field=r_ip

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
        require=False, validate=validators.Boolean())
    gettag = Option(
        doc='''
        **Syntax:** **gettag=***<y|n>*
        **Description:** Boolean to return attribute tags''',
        require=False, validate=validators.Boolean())
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
        require=False, validate=validators.Boolean())


    def stream(self, records):
        # Generate args
        my_args = prepare_config(self)
        my_args['misp_url'] = my_args['misp_url'] + '/attributes/restSearch'
        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['misp_key']
        headers['Accept'] = 'application/json'

        fieldname = str(self.field)
        if self.onlyids is True:
            to_ids = True
        else:
            to_ids = False
        if self.gettag is True:
            get_tag = True
        else:
            get_tag = False

        for record in records:
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    body_dict = { "returnFormat": "json"}
                    body_dict['value'] = str(value)
                    body_dict['withAttachments'] = "false"
                    if to_ids:
                        body_dict['to_ids'] = "True"
                    
                    body = json.dumps(body_dict)
                    misp_category = []
                    misp_event_id = []
                    misp_to_ids = []
                    misp_tag = []
                    misp_type = []
                    misp_value = []
                    misp_uuid = []
                    # search 
                    logging.info('INFO MISP REST API REQUEST: %s', body)
                    r = requests.post(my_args['misp_url'], headers=headers, data=body, verify=my_args['misp_verifycert'], proxies=my_args['proxies'])
                    # check if status is anything other than 200; throw an exception if it is
                    r.raise_for_status()
                    # response is 200 by this point or we would have thrown an exception
                    # print >> sys.stderr, "DEBUG MISP REST API response: %s" % response.json()
                    response = r.json()
                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            for a in response['response']['Attribute']:
                                if str(a['type']) not in misp_type:
                                    misp_type.append(str(a['type']))
                                if str(a['value']) not in misp_value:
                                    misp_value.append(str(a['value']))
                                if str(a['to_ids']) not in misp_to_ids:
                                    misp_to_ids.append(str(a['to_ids']))
                                if str(a['category']) not in misp_category:
                                    misp_category.append(str(a['category']))
                                if str(a['uuid']) not in misp_uuid:
                                    misp_uuid.append(str(a['uuid']))
                                if str(a['event_id']) not in misp_event_id:
                                    misp_event_id.append(str(a['event_id']))
                                if get_tag and 'Tag' in a:
                                    for tag in a['Tag']:
                                        if str(tag['name']) not in misp_tag:
                                            misp_tag.append(str(tag['name']))
                            record['misp_type'] = misp_type
                            record['misp_value'] = misp_value
                            record['misp_to_ids'] = misp_to_ids
                            record['misp_category'] = misp_category
                            record['misp_attribute_uuid'] = misp_uuid
                            record['misp_event_id'] = misp_event_id
                            if get_tag:
                                record['misp_tag'] = misp_tag

            yield record

if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)
    dispatch(MispSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)