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
import misp42splunk_declare

from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from misp_common import prepare_config, logging_level
import json
import logging
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# from splunklib.searchcommands import splunklib_logger as logger
import sys
from splunklib.six.moves import map
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(distributed=False)
class MispSightCommand(StreamingCommand):
    """
    search in MISP for attributes matching the value of field.

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
        **Description:**Name of the field containing \
        the value to search for.''',
        require=True, validate=validators.Fieldname())
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described \
        in local/misp42splunk_instances.conf.''',
        require=True)

    def stream(self, records):
        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if my_args is None:
            raise Exception("Sorry, no configuration for misp_instance={}".format(misp_instance))
        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['misp_key']
        headers['Accept'] = 'application/json'

        fieldname = str(self.field)
        search_url = my_args['misp_url'] + '/attributes/restSearch'
        sight_url = my_args['misp_url'] + \
            '/sightings/restSearch/attribute'

        for record in records:
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    search_dict = {"returnFormat": "json"}
                    search_dict['value'] = str(value)
                    search_dict['withAttachments'] = "false",
                    search_body = json.dumps(search_dict)

                    sight_dict = {"returnFormat": "json"}

                    misp_value = ''
                    misp_fp = False
                    misp_fp_ts = 0
                    misp_fp_id = ''
                    ms_seen = False
                    ms = {
                        'count': 0,
                        'first': 0,
                        'f_id': 0,
                        'last': 0,
                        'l_id': 0
                    }
                    # search
                    rs = requests.post(
                        search_url,
                        headers=headers,
                        data=search_body,
                        verify=my_args['misp_verifycert'],
                        cert=my_args['client_cert_full_path'],
                        proxies=my_args['proxies']
                    )
                    # check if status is anything other than 200;
                    # throw an exception if it is
                    # check if status is anything other than 200;
                    # throw an exception if it is
                    if rs.status_code in (200, 201, 204):
                        logging.info(
                            "[SI301] INFO mispsight part 1 successful. "
                            "url={}, HTTP status={}".format(my_args['misp_url'], rs.status_code)
                        )
                    else:
                        logging.error(
                            "[SI302] ERROR mispsight part 1 failed. "
                            "url={}, data={}, HTTP Error={}, content={}"
                            .format(my_args['misp_url'], search_body, rs.status_code, rs.text)
                        )
                        raise Exception(
                            "[SI302] ERROR mispsight part 1 failed. "
                            "url={}, data={}, HTTP Error={}, content={}"
                            .format(my_args['misp_url'], search_body, rs.status_code, rs.text)
                        )
                    # response is 200 by this point or we would
                    # have thrown an exception
                    response = rs.json()
                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            r_number = len(response['response']['Attribute'])
                            logging.info(
                                "MISP REST API %s: response: with %s records"
                                % (search_url, str(r_number))
                            )
                            for a in response['response']['Attribute']:
                                if misp_value == '':
                                    misp_value = str(a['value'])
                                if misp_fp is False:
                                    sight_dict['id'] = str(a['id'])
                                    sight_body = json.dumps(sight_dict)
                                    rt = requests.post(
                                        sight_url,
                                        headers=headers,
                                        data=sight_body,
                                        verify=my_args['misp_verifycert'],
                                        cert=my_args['client_cert_full_path'],
                                        proxies=my_args['proxies']
                                    )
                                    # check if status is anything
                                    # other than 200; throw an exception
                                    if rt.status_code in (200, 201, 204):
                                        logging.info(
                                            "[SI301] INFO mispsight part 2 successful. "
                                            "url={}, HTTP status={}".format(my_args['misp_url'], rt.status_code)
                                        )
                                    else:
                                        logging.error(
                                            "[SI302] ERROR mispsight part 2 failed. "
                                            "url={}, data={}, HTTP Error={}, content={}"
                                            .format(my_args['misp_url'], sight_body, rt.status_code, rt.text)
                                        )
                                        raise Exception(
                                            "[SI302] ERROR mispsight part 2 failed. "
                                            "url={}, data={}, HTTP Error={}, content={}"
                                            .format(my_args['misp_url'], sight_body, rt.status_code, rt.text)
                                        )
                                    # response is 200 by this point or we
                                    # would have thrown an exception
                                    sight = rt.json()
                                    if 'response' in sight:
                                        for s in sight['response']:
                                            if 'Sighting' in s:
                                                # true sighting
                                                ty = s['Sighting']['type']
                                                ds = int(
                                                    s['Sighting']
                                                    ['date_sighting']
                                                )
                                                ev = str(
                                                    s['Sighting']
                                                    ['event_id']
                                                )
                                                if int(ty) == 0:
                                                    ms_seen = True
                                                    ms['count'] = \
                                                        ms['count'] + 1
                                                    if ms['first'] == 0 or \
                                                       ms['first'] > ds:
                                                        ms['first'] = ds
                                                        ms['f_id'] = ev
                                                    if ms['last'] < int(ds):
                                                        ms['last'] = int(ds)
                                                        ms['l_id'] = ev
                                                # false positive
                                                elif int(ty) == 1:
                                                    misp_fp = True
                                                    misp_fp_ts = ds
                                                    misp_fp_id = ev
                            if misp_fp is True:
                                record['misp_value'] = misp_value
                                record['misp_fp'] = "True"
                                record['misp_fp_timestamp'] = str(
                                    misp_fp_ts
                                )
                                record['misp_fp_event_id'] = str(
                                    misp_fp_id
                                )
                            if ms_seen is True:
                                record['misp_value'] = misp_value
                                record['misp_count'] = str(ms['count'])
                                record['misp_first'] = str(ms['first'])
                                record['misp_first_event_id'] = str(
                                    ms['f_id']
                                )
                                record['misp_last'] = str(ms['last'])
                                record['misp_last_event_id'] = str(
                                    ms['l_id']
                                )
            yield record


if __name__ == "__main__":
    # set up custom logger for the app commands
    logging.root
    loglevel = logging_level('misp42splunk')
    logging.root.setLevel(loglevel)
    logging.error('logging level is set to %s', loglevel)
    logging.error('PYTHON VERSION: ' + sys.version)
    dispatch(MispSightCommand, sys.argv, sys.stdin, sys.stdout, __name__)
