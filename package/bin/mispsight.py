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
from misp_common import prepare_config, logging_level, urllib_init_pool, urllib_request
import json
import logging
import sys
·
__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.3.0"
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

    def log_error(self, msg):
        logging.error(msg)

    def log_info(self, msg):
        logging.info(msg)

    def log_debug(self, msg):
        logging.debug(msg)

    def log_warn(self, msg):
        logging.warning(msg)

    def set_log_level(self):
        logging.root
        loglevel = logging_level('misp42splunk')
        logging.root.setLevel(loglevel)
        logging.error('[SI-101] logging level is set to %s', loglevel)
        logging.error('[SI-102] PYTHON VERSION: ' + sys.version)

    @staticmethod
    def _sight_metric(m, sname, srec):
        ds = int(srec['date_sighting'])
        m['misp_sight_' + sname + '_count'] = m['misp_sight_' + sname + '_count'] + 1
        if m['misp_sight_' + sname + '_et'] in [None, ''] or \
           int(m['misp_sight_' + sname + '_et']) > ds:
            m['misp_sight_' + sname + '_et'] = ds
            m['misp_sight_' + sname + '_first_a_id'] = srec['attribute_id']
            m['misp_sight_' + sname + '_first_e_id'] = srec['event_id']
            m['misp_sight_' + sname + '_first_org_id'] = srec['org_id']
            m['misp_sight_' + sname + '_first_source'] = srec['source']

        if m['misp_sight_' + sname + '_lt'] in [None, ''] or \
           int(m['misp_sight_' + sname + '_lt']) < ds:
            m['misp_sight_' + sname + '_lt'] = ds
            m['misp_sight_' + sname + '_last_a_id'] = srec['attribute_id']
            m['misp_sight_' + sname + '_last_e_id'] = srec['event_id']
            m['misp_sight_' + sname + '_last_org_id'] = srec['org_id']
            m['misp_sight_' + sname + '_last_source'] = srec['source']


    def stream(self, records):
        # loggging
        self.set_log_level()
        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if my_args is None:
            raise Exception("Sorry, no configuration for misp_instance={}".format(misp_instance))

        fieldname = str(self.field)
        search_url = my_args['misp_url'] + '/attributes/restSearch'
        sight_url_base = my_args['misp_url'] + '/sightings/index/'

        response = None
        connection, connection_status = urllib_init_pool(self, my_args)

        # iterate through records from SPL
        for record in records:
            # if a record contains the field passed to mispsight command
            # search by value in MISP to get attribute local ID.
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    search_dict = dict(
                        returnFormat='json',
                        value=str(value),
                        withAttachments="false")
                    if connection:
                        response = urllib_request(
                            self, connection, 'POST',
                            search_url, search_dict, my_args)
                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            # MISP API returned a JSON response
                            r_number = len(response['response']['Attribute'])
                            self.log_info(
                                "MISP REST API {}: response: with {} records"
                                .format(search_url, str(r_number))
                            )

                            event_list = list()
                            attribute_list = dict()
                            for a in response['response']['Attribute']:
                                if a['event_id'] not in event_list:
                                    event_list.append(a['event_id'])
                                if a['id'] not in attribute_list:
                                    attribute_list[a['id']] = a['value']

                            sightings = dict()
                            sight_types = ['t0', 't1', 't2']
                            metrics = [
                                'et', 'lt',
                                'first_a_id', 'last_a_id',
                                'first_e_id', 'last_e_id',
                                'first_org_id', 'last_org_id',
                                'first_source', 'last_source']
                            sight_counter = {
                                'misp_value': ''
                                # 'misp_sightings': []
                            }
                            for stype in sight_types:
                                skey = 'misp_sight_' + stype + '_count'
                                sight_counter[skey] = 0
                                for metric in metrics:
                                    skey = 'misp_sight_' + stype + '_' + metric
                                    sight_counter[skey] = ''

                            # iterate through results to get sighting counters
                            sight_dict = {"returnFormat": "json"}
                            for e in event_list:
                                sight_url = sight_url_base + e
                                sight = urllib_request(
                                    self, connection, 'GET',
                                    sight_url, sight_dict, my_args)
                                for s in sight:
                                    if s['attribute_id'] in attribute_list:
                                        misp_value = str(
                                            attribute_list[s['attribute_id']])
                                        if misp_value in sightings:
                                            a_sight = sightings[misp_value]
                                        else:
                                            a_sight = sight_counter.copy()
                                            a_sight['misp_value'] = misp_value
                                        # true sighting
                                        ty = int(s['type'])
                                        if ty == 0:
                                            MispSightCommand._sight_metric(a_sight, 't0', s)
                                        elif ty == 1:
                                            MispSightCommand._sight_metric(a_sight, 't1', s)
                                        elif ty == 2:
                                            MispSightCommand._sight_metric(a_sight, 't2', s)

                                        sightings[misp_value] = a_sight

                            init_record = True
                            for srec in sightings.values():
                                if init_record is True:
                                    for key, value in sorted(srec.items()):
                                        record[key] = [value]
                                    init_record = False
                                else:
                                    for key, value in sorted(srec.items()):
                                        record[key].append(value)

            yield record


if __name__ == "__main__":
    dispatch(MispSightCommand, sys.argv, sys.stdin, sys.stdout, __name__)
