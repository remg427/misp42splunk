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
import logging
from misp_common import prepare_config, logging_level

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.1.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


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

    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described in local/inputs.conf''',
        require=True)
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
    includeEventUuid = Option(
        doc='''
        **Syntax:** **includeEventUuid=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to include event UUID(s) to results.''',
        require=False, validate=validators.Boolean())
    includeEventTags = Option(
        doc='''
        **Syntax:** **includeEventTags=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to include event UUID(s) to results.''',
        require=False, validate=validators.Boolean())
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:**publication duration in day(s), hour(s) or minute(s). **eventid**, **last** and **date_from** are mutually exclusive''',
        require=False, validate=validators.Match("last", r"^[0-9]+[hdm]$"))
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search; default 1000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False)


    def stream(self, records):
        # Generate args
        my_args = prepare_config(self)
        my_args['misp_url'] = my_args['misp_url'] + '/attributes/restSearch'
        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['misp_key']
        headers['Accept'] = 'application/json'

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
            logging.info('Option "json_request" set')
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
            if self.onlyids is True:
                body_dict['to_ids'] = "True"
            if self.includeEventUuid is not None:
                body_dict['includeEventUuid'] = self.includeEventUuid
            if self.includeEventTags is not None:
                body_dict['includeEventTags'] = self.includeEventTags
            if self.last is not None:
                body_dict['last'] = self.last
        for record in records:
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    body_dict['value'] = str(value)
                    misp_category = []
                    misp_event_id = []
                    misp_event_uuid = []
                    misp_orgc_id = []
                    misp_to_ids = []
                    misp_tag = []
                    misp_type = []
                    misp_value = []
                    misp_uuid = []
                    # search
                    if pagination is True:
                        body_dict['page'] = page
                        body_dict['limit'] = limit
                    body = json.dumps(body_dict)
                    logging.debug('mispsearch request body: %s', body)
                    r = requests.post(my_args['misp_url'], headers=headers,
                                      data=body,
                                      verify=my_args['misp_verifycert'],
                                      cert=my_args['client_cert_full_path'],
                                      proxies=my_args['proxies'])
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
                                if 'Tag' in a:
                                    for tag in a['Tag']:
                                        if str(tag['name']) not in misp_tag:
                                            misp_tag.append(str(tag['name']))
                                if 'Event' in a:
                                    if a['Event']['uuid'] not in misp_event_uuid:
                                        misp_event_uuid.append(str(a['Event']['uuid']))
                                    if a['Event']['orgc_id'] not in misp_orgc_id:
                                        misp_orgc_id.append(str(a['Event']['orgc_id']))
                            record['misp_type'] = misp_type
                            record['misp_value'] = misp_value
                            record['misp_to_ids'] = misp_to_ids
                            record['misp_category'] = misp_category
                            record['misp_attribute_uuid'] = misp_uuid
                            record['misp_event_id'] = misp_event_id
                            record['misp_event_uuid'] = misp_event_uuid
                            record['misp_orgc_id'] = misp_orgc_id
                            record['misp_tag'] = misp_tag
            yield record


if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    loglevel = logging_level()
    logging.error('logging level is set to %s', loglevel)
    logging.root.setLevel(loglevel)
    dispatch(MispSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
