#!/usr/bin/env python
# coding=utf-8
#
# MISP API wrapper reporting command
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#

from __future__ import absolute_import, division, print_function, unicode_literals
import sys
import requests
import json

from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators
import logging
from misp_common import prepare_config


__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "3.1.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(requires_preop=False)
class mispgetevent(ReportingCommand):
    """ MISP API wrapper for endpoint /attributes/restSearch.
    return format is JSON for the momemnt
    ##Syntax
    use paramater names to set values in the POST request body below.
    .. code-block::
        | mispgetevent misp_instance=<input> page=<int> limit=<int> value=string type=CSVstring category=CSVstring org=string 
                        tags=CSVstring not_tags=CSVstrings date_from=date_string date_to=date_string last=<int>(d|h|m)
                        eventid=CSVint uuid=CSVuuid_string enforceWarninglist=True|False 
                        to_ids=True|False deleted=True|False includeEventUuid=True|False includeEventTags==True|False
                        threat_level_id=<int> eventinfo=string

    forced parameters:
        "returnFormat": "json"
        withAttachments: False
    not handled parameters:
        "publish_timestamp": "optional",
        "timestamp": "optional",
        "event_timestamp": "optional",


    ##Description
    {
        "returnFormat": "mandatory",
        "page": "optional",
        "limit": "optional",
        "value": "optional",
        "type": "optional",
        "category": "optional",
        "org": "optional",
        "tag": "optional",
        "tags": "optional",
        "searchall": "optional",
        "date": "optional",
        "last": "optional",
        "eventid": "optional",
        "withAttachments": "optional",
        "metadata": "optional",
        "uuid": "optional",
        "published": "optional",
        "publish_timestamp": "optional",
        "timestamp": "optional",
        "enforceWarninglist": "optional",
        "sgReferenceOnly": "optional",
        "eventinfo": "optional",
        "excludeLocalTags": "optional"
    }
    # status for mode=p
    {
        "returnFormat": forced to JSON
        "page": "optional",
        "limit": "optional",
        "value": "optional",
        "type": "optional",
        "category": "optional",
        "org": "optional",
        "tag": "optional",
        "tags": "optional",
        "searchall": "optional",
        "date": "optional",
        "last": "optional",
        "eventid": "optional",
        "withAttachments": forced to False
        "metadata": "optional",
        "uuid": "optional",
        "published": "optional",
        "publish_timestamp": "optional",
        "timestamp": "optional",
        "enforceWarninglist": "optional",
        "sgReferenceOnly": "optional",
        "eventinfo": "optional",
        "excludeLocalTags": "optional"
    }
    """
    # Superseede MISP instance for this search
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described in local/inputs.conf.''',
        require=True)
    # if mode=j a complete JSON request has to be provided
    json_request=Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False)
    # specific formats
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:**publication duration in day(s), hour(s) or minute(s).''',
        require=False, validate=validators.Match("last", r"^[0-9]+[hdm]$"))
    threat_level_id = Option(
        doc='''
        **Syntax:** **threat_level_id=***1-4*
        **Description:**Threat level.''',
        require=False, validate=validators.Match("threat_level_id", r"^[1-4]$"))
    org = Option(
        doc='''
        **Syntax:** **org=***CSV string*
        **Description:**Comma(,)-separated string of org name(s), id(s), uuid(s).''',
        require=False)
    # CSV numeric list
    eventid = Option(
        doc='''
        **Syntax:** **eventid=***id1(,id2,...)*
        **Description:**list of event ID(s).''',
        require=False, validate=validators.Match("eventid", r"^[0-9,]+$"))
    # strings
    value = Option(
        doc='''
        **Syntax:** **value=***string*
        **Description:**value.''',
        require=False)
    eventinfo = Option(
        doc='''
        **Syntax:** **eventinfo=***string*
        **Description:**eventinfo string''',
        require=False)
    # numeric values
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search; default 10000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page of result to get.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    # CSV strings       
    uuid = Option(
        doc='''
        **Syntax:** **uuid=***id1(,id2,...)*
        **Description:**list of event UUID(s).''',
        require=False)
    type = Option(
        doc='''
        **Syntax:** **type=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    category = Option(
        doc='''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    tags = Option(
        doc='''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for. Wildcard is %.''',
        require=False)
    not_tags = Option(
        doc='''
        **Syntax:** **not_tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to exclude from results. Wildcard is %.''',
        require=False)
    # Booleans
    enforceWarninglist = Option(
        doc='''
        **Syntax:** **enforceWarninglist=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to apply warning lists to results.''',
        require=False, validate=validators.Boolean())
    excludeLocalTags = Option(
        doc='''
        **Syntax:** **includeEventTags=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to include event UUID(s) to results.''',
        require=False, validate=validators.Boolean())

    @Configuration()
    def map(self, records):
        # self.logger.debug('mispgetioc.map')
        return records

    def reduce(self, records):

        # Phase 1: Preparation
        my_args = prepare_config(self)
        my_args['misp_url'] = my_args['misp_url'] + '/events/restSearch'

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
            # add provided parameters to JSON request body
            # specific formats
            if self.last is not None:
                body_dict['last'] = self.last
                logging.info('Option "last" set with %s', body_dict['last'])

            if self.threat_level_id is not None:
                body_dict['threat_level_id'] = self.threat_level_id
                logging.info('Option "threat_level_id" set with %s', body_dict['threat_level_id'])

            if self.org is not None:
                body_dict['org'] = self.org
                logging.info('Option "org" set')

            if self.eventid:
                if "," in self.eventid:
                    event_criteria = {}
                    event_list = self.eventid.split(",")
                    event_criteria['OR'] = event_list
                    body_dict['eventid'] = event_criteria
                else:
                    body_dict['eventid'] = self.eventid
                logging.info('Option "eventid" set')

            if self.value is not None:
                body_dict['value'] = self.value
                logging.info('Option "value" set')

            if self.eventinfo is not None:
                body_dict['eventinfo'] = self.eventinfo
                logging.info('Option "eventinfo" set')

            # CSV strings
            if self.category is not None:
                cat_criteria = {}
                cat_list = self.category.split(",")
                cat_criteria['OR'] = cat_list
                body_dict['category'] = cat_criteria
            if self.type is not None:
                type_criteria = {}
                type_list = self.type.split(",")
                type_criteria['OR'] = type_list
                body_dict['type'] = type_criteria
            if self.tags is not None or self.not_tags is not None:
                tags_criteria = {}
                if self.tags is not None:
                    tags_list = self.tags.split(",")
                    tags_criteria['OR'] = tags_list
                if self.not_tags is not None:
                    tags_list = self.not_tags.split(",")
                    tags_criteria['NOT'] = tags_list
                body_dict['tags'] = tags_criteria
            if self.uuid is not None:
                uuid_criteria = {}
                uuid_list = self.uuid.split(",")
                uuid_criteria['OR'] = uuid_list
                body_dict['uuid'] = uuid_criteria

            # Booleans
            if self.enforceWarninglist is not None:
                body_dict['enforceWarninglist'] = self.enforceWarninglist
                logging.info('Option "enforceWarninglist" set with %s', body_dict['enforceWarninglist'])

            if self.excludeLocalTags is not None:
                body_dict['includeEventTags'] = self.includeEventTags
                logging.info('Option "includeEventTags" set with %s', body_dict['includeEventTags'])
        # set proper headers

        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['misp_key']
        headers['Accept'] = 'application/json'

        results = []
        # add colums for each type in results
        if pagination is True:
            body_dict['page'] = page
            body_dict['limit'] = limit

        body = json.dumps(body_dict)
        logging.debug('mispgetevent request body: %s', body)
        # search
        r = requests.post(my_args['misp_url'], headers=headers, data=body, verify=my_args['misp_verifycert'], cert=my_args['client_cert_full_path'], proxies=my_args['proxies'])
        # check if status is anything other than 200; throw an exception if it is
        r.raise_for_status()
        # response is 200 by this point or we would have thrown an exception
        response = r.json()
        if 'response' in response:
            if 'Attribute' in response['response']:
                for a in response['response']['Attribute']:
                    v = {}
                    v['misp_Object'] = "-"
                    if self.includeEventTags is True:
                        v['misp_tag'] = "-"
                    for ak, av in a.items():
                        if ak == 'Event':
                            json_event = a['Event']
                            for ek, ev in json_event.items():
                                key = 'misp_event_' + ek
                                v[key] = str(ev)
                        elif ak == 'Tag':
                            tag_list = []
                            for tag in a['Tag']:
                                try:
                                    tag_list.append(str(tag['name']))
                                except Exception:
                                    pass
                            v['misp_tag'] = tag_list
                        else:
                            vkey = 'misp_' + ak
                            v[vkey] = av
                    results.append(v)

        # add colums for each type in results
        typelist = []
        for r in results:
            if r['misp_type'] not in typelist:
                typelist.append(r['misp_type'])

        output_dict = {}
        increment = 1
        for r in results:
            key = str(r['misp_event_id']) + '_' + str(increment)
            increment = increment + 1
            v = r
            for t in typelist:
                misp_t = 'misp_' + t.replace('-', '_').replace('|', '_p_')
                if t == r['misp_type']:
                    v[misp_t] = r['misp_value']
                else:
                    v[misp_t] = ''
            output_dict[key] = v

        for k, v in output_dict.items():
            yield v


if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)
    dispatch(mispgetevent, sys.argv, sys.stdin, sys.stdout, __name__)
