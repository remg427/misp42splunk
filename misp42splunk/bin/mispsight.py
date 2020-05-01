# coding=utf-8
#
# search for value in MISP and add some fields to the pipeline
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
from __future__ import absolute_import
from __future__ import print_function
from __future__ import division
from __future__ import unicode_literals
from misp_common import prepare_config, logging_level
import json
import logging
import os
import requests
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
from splunklib.searchcommands import dispatch, StreamingCommand, \
    Configuration, Option, validators


__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "3.1.10"
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
        **Description:**Name of the field containing \
        the value to search for.''',
        require=True, validate=validators.Fieldname())
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described \
        in local/inputs.conf.''',
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
                    logging.debug('mispsight request body: %s', search_body)
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
                    rs.raise_for_status()
                    # response is 200 by this point or we would
                    # have thrown an exception
                    response = rs.json()
                    logging.info("MISP REST API %s has got a response with \
                        status code 200", search_url)
                    logging.debug(
                        "MISP REST API %s has got a response: %s"
                        % (search_url, json.dumps(response))
                    )
                    if 'response' in response:
                        if 'Attribute' in response['response']:
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
                                    rt.raise_for_status()
                                    # response is 200 by this point or we
                                    # would have thrown an exception
                                    sight = rt.json()
                                    logging.info(
                                        "MISP REST API %s has got a response \
                                        with status code 200",
                                        sight_url
                                    )
                                    logging.debug(
                                        "MISP REST API %s has got a response: \
                                        %s" % (
                                            sight_url,
                                            json.dumps(sight)
                                        )
                                    )
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
    # set up logging suitable for splunkd consumption
    logging.root
    loglevel = logging_level()
    logging.error('logging level is set to %s', loglevel)
    logging.root.setLevel(loglevel)
    dispatch(mispsight, sys.argv, sys.stdin, sys.stdout, __name__)
