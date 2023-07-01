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

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.2.1"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(distributed=False)
class MispSearchCommand(StreamingCommand):
    """
    search in MISP for attributes matching the value of field.

    ##Syntax

        code-block::
        mispsearch field=<field> to_ids=y|n

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

    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as \
        described in local/misp42splunk_instances.conf''',
        require=True)
    field = Option(
        doc='''
        **Syntax:** **field=***<fieldname>*
        **Description:**Name of the field containing \
        the value to search for.''',
        require=True, validate=validators.Fieldname())
    to_ids = Option(
        doc='''
        **Syntax:** **to_ids=***<y|n>*
        **Description:** Boolean to search only attributes with to_ids set''',
        require=False, validate=validators.Boolean())
    includeEventUuid = Option(
        doc='''
        **Syntax:** **includeEventUuid=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to include event UUID(s) to results.''',
        require=False, validate=validators.Boolean())
    includeEventTags = Option(
        doc='''
        **Syntax:** **includeEventTags=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to include Event Tags to results.''',
        require=False, validate=validators.Boolean())
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:**Publication duration in day(s), hour(s) or minute(s) 
        to limit search scope only to published events in last X timerange.''',
        require=False, validate=validators.Match("last", r"^[0-9]+[hdm]$"))
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search; \
        default 1000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("page", r"^[0-9]+$"))
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False)

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
        logging.error('[SE-101] logging level is set to %s', loglevel)
        logging.error('[SE-102] PYTHON VERSION: ' + sys.version)

    def stream(self, records):
        # loggging
        self.set_log_level()
        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if my_args is None:
            raise Exception("Sorry, no configuration for misp_instance={}".format(misp_instance))
        my_args['misp_url'] = my_args['misp_url'] + '/attributes/restSearch'

        fieldname = str(self.field)
        pagination = True
        if self.limit is not None:
            if int(self.limit) == 0:
                pagination = False
            else:
                limit = int(self.limit)
        else:
            limit = 1000
        if self.page is not None:
            page = int(self.page)
        else:
            page = 1

        if self.json_request is not None:
            body_dict = json.loads(self.json_request)
            self.log_info('Option "json_request" set')
            body_dict['returnFormat'] = 'json'
            body_dict['withAttachments'] = False
            if 'limit' in body_dict:
                limit = int(body_dict['limit'])
                if limit == 0:
                    pagination = False
            if 'page' in body_dict:
                page = body_dict['page']
                pagination = False
        else:
            # build search JSON object
            body_dict = {"returnFormat": "json",
                         "withAttachments": False
                         }
            if self.to_ids is True:
                body_dict['to_ids'] = "True"
            if self.includeEventUuid is not None:
                body_dict['includeEventUuid'] = self.includeEventUuid
            if self.includeEventTags is not None:
                body_dict['includeEventTags'] = self.includeEventTags
            if self.last is not None:
                body_dict['last'] = self.last

        response = None
        connection, connection_status = urllib_init_pool(self, my_args)

        {for record in records:}
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    body_dict['value'] = str(value)
                    misp_category = []
                    misp_event_id = []
                    misp_event_uuid = []
                    misp_orgc_id = []
                    misp_to_ids = []
                    misp_comment = []
                    misp_tag = []
                    misp_type = []
                    misp_value = []
                    misp_uuid = []
                    # search
                    if pagination is True:
                        body_dict['page'] = page
                        body_dict['limit'] = limit

                    if connection:
                        response = urllib_request(self,
                                                  connection,
                                                  'POST',
                                                  my_args['misp_url'],
                                                  body_dict,
                                                  my_args)

                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            for a in response['response']['Attribute']:
                                if str(a['type']) not in misp_type:
                                    misp_type.append(str(a['type']))
                                if str(a['value']) not in misp_value:
                                    misp_value.append(str(a['value']))
                                if str(a['to_ids']) not in misp_to_ids:
                                    misp_to_ids.append(str(a['to_ids']))
                                if str(a['comment']) not in misp_comment:
                                    misp_comment.append(str(a['comment']))
                                if str(a['category']) not in misp_category:
                                    misp_category.append(str(a['category']))
                                if str(a['uuid']) not in misp_uuid:
                                    misp_uuid.append(str(a['uuid']))
                                if str(a['event_id']) not in misp_event_id:
                                    misp_event_id.append(str(a['event_id']))
                                if 'Tag' in a:
                                    for tag in a['Tag']:
                                        if str(tag['name']) not in misp_tag:
                                            misp_tag.append(str(tag['name']))
                                if 'Event' in a:
                                    if a['Event']['uuid'] \
                                       not in misp_event_uuid:
                                        misp_event_uuid.append(
                                            str(a['Event']['uuid']))
                                    if a['Event']['orgc_id'] \
                                       not in misp_orgc_id:
                                        misp_orgc_id.append(
                                            str(a['Event']['orgc_id']))
                            record['misp_type'] = misp_type
                            record['misp_value'] = misp_value
                            record['misp_to_ids'] = misp_to_ids
                            record['misp_comment'] = misp_comment
                            record['misp_category'] = misp_category
                            record['misp_attribute_uuid'] = misp_uuid
                            record['misp_event_id'] = misp_event_id
                            record['misp_event_uuid'] = misp_event_uuid
                            record['misp_orgc_id'] = misp_orgc_id
                            record['misp_tag'] = misp_tag
            yield record


if __name__ == "__main__":
    dispatch(MispSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
