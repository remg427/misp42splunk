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
from __future__ import absolute_import, division, print_function, unicode_literals
import json
import logging
import os
import requests
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from misp_common import prepare_config, logging_level


__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "3.1.6"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(distributed=False)
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
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described in local/inputs.conf.''',
        require=True)

    def stream(self, records):
        # self.logger.debug('mispgetioc.reduce')

        # Generate args
        my_args = prepare_config(self)
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
                    logging.debug('mispsight request body: %s', search_body)
                    r = requests.post(search_url, headers=headers, data=search_body, verify=my_args['misp_verifycert'], cert=my_args['client_cert_full_path'], proxies=my_args['proxies'])
                    # check if status is anything other than 200; throw an exception if it is
                    r.raise_for_status()
                    # response is 200 by this point or we would have thrown an exception
                    response = r.json()
                    logging.info("MISP REST API %s has got a response with status code 200", search_url)
                    logging.debug("MISP REST API %s has got a response: %s" % (search_url, r.json()))
                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            for a in response['response']['Attribute']:
                                if misp_value == '':
                                    misp_value = str(a['value'])
                                if misp_fp == False:
                                    sight_dict['id'] = str(a['id'])
                                    sight_body = json.dumps(sight_dict)
                                    s = requests.post(sight_url, headers=headers, data=sight_body, verify=my_args['misp_verifycert'], cert=my_args['client_cert_full_path'], proxies=my_args['proxies'])
                                    # check if status is anything other than 200; throw an exception if it is
                                    s.raise_for_status()
                                    # response is 200 by this point or we would have thrown an exception
                                    sight = s.json()
                                    logging.info("MISP REST API %s has got a response with status code 200", sight_url)
                                    logging.debug("MISP REST API %s has got a response: %s" % (sight_url, s.json()))
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
    loglevel = logging_level()
    logging.error('logging level is set to %s', loglevel)
    logging.root.setLevel(loglevel)
    dispatch(mispsight, sys.argv, sys.stdin, sys.stdout, __name__)
