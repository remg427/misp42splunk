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

class mispsight(StreamingCommand):
    """ search in MISP for attributes matching the value of field.

    ##Syntax

        code-block::
        mispsearch field=<field> onlyids=y|n

    ##Description

        search_body = {"returnFormat": "json",
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
            my_args['misp_url'] = self.misp_url
            logging.debug('misp_url as option, value is %s', my_args['misp_url'])
        else:
            my_args['misp_url'] = mispconf.get('mispsetup', 'misp_url')
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

        for record in records:
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    search_url = my_args['misp_url'] + '/attributes/restSearch'
                    search_dict = { "returnFormat": "json"}
                    search_dict['value'] = str(value)
                    search_dict['withAttachments'] = "false",
                    search_body = json.dumps(search_dict)

                    sight_url = my_args['misp_url'] + '/sightings/restSearch/attribute'
                    sight_dict = { "returnFormat": "json"}

                    misp_value = ''
                    misp_fp = False
                    misp_fp_timestamp = 0
                    misp_fp_event_id = ''
                    misp_sight_seen = False
                    misp_sight = {
                        'count': 0,
                        'first': 0,
                        'first_event_id': 0,
                        'last': 0,
                        'last_event_id': 0
                    }
                    # search
                    r = requests.post(search_url, headers=headers, data=search_body, verify=my_args['misp_verifycert'])
                    # check if status is anything other than 200; throw an exception if it is
                    r.raise_for_status()
                    # response is 200 by this point or we would have thrown an exception
                    # print >> sys.stderr, "DEBUG MISP REST API response: %s" % response.json()
                    response = r.json()
                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            for a in response['response']['Attribute']:
                                if misp_value == '':
                                    misp_value = str(a['value'])
                                if misp_fp == False:
                                    sight_dict['id'] = str(a['id'])
                                    sight_body = json.dumps(sight_dict)
                                    s = requests.post(sight_url, headers=headers, data=sight_body, verify=my_args['misp_verifycert'])
                                    # check if status is anything other than 200; throw an exception if it is
                                    s.raise_for_status()
                                    # response is 200 by this point or we would have thrown an exception
                                    # print >> sys.stderr, "DEBUG MISP REST API response: %s" % response.json()
                                    sight = s.json()
                                    if 'response' in sight:
                                        for se in sight['response']:
                                            if 'Sighting' in se:
                                                if int(se['Sighting']['type']) == 0:  #true sighting
                                                    misp_sight_seen = True
                                                    misp_sight['count'] = misp_sight['count'] + 1
                                                    if misp_sight['first'] == 0 or \
                                                       misp_sight['first'] > int(se['Sighting']['date_sighting']):
                                                        misp_sight['first'] = int(se['Sighting']['date_sighting'])
                                                        misp_sight['first_event_id'] = se['Sighting']['event_id']
                                                    if misp_sight['last'] < int(se['Sighting']['date_sighting']):
                                                        misp_sight['last'] = int(se['Sighting']['date_sighting'])
                                                        misp_sight['last_event_id'] = se['Sighting']['event_id']
                                                elif int(se['Sighting']['type']) == 1:  #false positive
                                                    misp_fp = True
                                                    misp_fp_timestamp = int(se['Sighting']['date_sighting'])
                                                    misp_fp_event_id = se['Sighting']['event_id']
                            if misp_fp == True:
                                record['misp_value'] = misp_value
                                record['misp_fp'] = "True"
                                record['misp_fp_timestamp'] = str(misp_fp_timestamp)
                                record['misp_fp_event_id'] = str(misp_fp_event_id)
                            if misp_sight_seen == True:
                                record['misp_value'] = misp_value
                                record['misp_sight_count'] = str(misp_sight['count'])
                                record['misp_sight_first'] = str(misp_sight['first'])
                                record['misp_sight_first_event_id'] = str(misp_sight['first_event_id'])
                                record['misp_sight_last'] = str(misp_sight['last'])
                                record['misp_sight_last_event_id'] = str(misp_sight['last_event_id'])
            yield record

if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)
    dispatch(mispsight, sys.argv, sys.stdin, sys.stdout, __name__)