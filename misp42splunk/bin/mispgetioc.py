# coding=utf-8
#
# Extract IOC's from MISP
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
# "warning_list": "optional",

from __future__ import absolute_import, division, print_function, unicode_literals
import misp42splunk_declare

from collections import OrderedDict
from itertools import chain
import json
import logging
from misp_common import prepare_config, logging_level
import requests
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
# from splunklib.searchcommands import splunklib_logger as logger
import sys
from splunklib.six.moves import map

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "3.1.13"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(retainsevents=False, type='reporting', distributed=False)
class MispGetIocCommand(GeneratingCommand):
    """ get the attributes from a MISP instance.
    ##Syntax
    .. code-block::
        | mispgetioc misp_instance=<input> last=<int>(d|h|m)
        | mispgetioc misp_instance=<input> event=<id1>(,<id2>,...)
        | mispgetioc misp_instance=<input> date=<<YYYY-MM-DD>
                                           (date_to=<YYYY-MM-DD>)
    ##Description
    {
        "returnFormat": "mandatory",
        "page": "optional",
        "limit": "optional",
        "value": "optional",
        "type": "optional",
        "category": "optional",
        "org": "optional",
        "tags": "optional",
        "date": "optional",
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
        "eventinfo": "optional",
        "includeProposals": "optional",
        "includeDecayScore": "optional",
        "includeFullModel": "optional",
        "decayingModel": "optional",
        "excludeDecayed": "optional",
        "score": "optional"
    }
    # status
        "returnFormat": forced to json,
        "page": param,
        "limit": param,
        "value": not managed,
        "type": param, CSV string,
        "category": param, CSV string,
        "org": not managed,
        "tags": param, see also not_tags
        "date": param,
        "last": param,
        "eventid": param,
        "withAttachments": forced to false,
        "uuid": not managed,
        "publish_timestamp": managed via param last
        "timestamp": not managed,
        "enforceWarninglist": param,
        "to_ids": param,
        "deleted": forced to False,
        "includeEventUuid": set to True,
        "includeEventTags": param,
        "event_timestamp":  not managed,
        "threat_level_id":  not managed,
        "eventinfo": not managed,
        "includeProposals": not managed
        "includeDecayScore": not managed,
        "includeFullModel": not managed,
        "decayingModel": not managed,
        "excludeDecayed": not managed,
        "score": not managed
    }
    """
    # MANDATORY MISP instance for this search
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:** MISP instance parameters
        as described in local/inputs.conf.''',
        require=True)
    # MANDATORY: json_request XOR eventid XOR last XOR date
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False)
    eventid = Option(
        doc='''
        **Syntax:** **eventid=***id1(,id2,...)*
        **Description:**list of event ID(s) or event UUID(s).''',
        require=False, validate=validators.Match("eventid", r"^[0-9a-f,\-]+$"))
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:** publication duration in day(s), hour(s) or minute(s).
        **nota bene:** last is an alias of published_timestamp''',
        require=False, validate=validators.Match("last", r"^[0-9]+[hdm]$"))
    date = Option(
        doc='''
        **Syntax:** **date=***The user set event date field
         - any of valid time related filters"*
        **Description:**starting date.
         **eventid**, **last** and **date** are mutually exclusive''',
        require=False)
    # Other params
    add_description = Option(
        doc='''
        **Syntax:** **add_description=***<1|y|Y|t|true|True
        |0|n|N|f|false|False>*
        **Description:**Boolean to return misp_description.''',
        require=False, validate=validators.Boolean())
    category = Option(
        doc='''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for.
         Wildcard is %.''',
        require=False)
    geteventtag = Option(
        doc='''
        **Syntax:** **geteventtag=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean includeEventTags. By default only
         attribute tag(s) are returned.''',
        require=False, validate=validators.Boolean())
    getorg = Option(
        doc='''
        **Syntax:** **getorg=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return the ID of the organisation that
         created the event.''',
        require=False, validate=validators.Boolean())
    getuuid = Option(
        doc='''
        **Syntax:** **getuuid=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return attribute UUID.''',
        require=False, validate=validators.Boolean())
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search;
         default 1000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    not_tags = Option(
        doc='''
        **Syntax:** **not_tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to exclude.
         Wildcard is %.''',
        require=False)
    output = Option(
        doc='''
        **Syntax:** **output=***<default|rawy>*
        **Description:**selection between the default behaviou or \
        JSON output by event.''',
        require=False, validate=validators.Match(
            "output", r"(default|raw)"))
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    pipesplit = Option(
        doc='''
        **Syntax:** **pipesplit=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to split multivalue attributes.''',
        require=False, validate=validators.Boolean())
    tags = Option(
        doc='''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for.
         Wildcard is %.''',
        require=False)
    to_ids = Option(
        doc='''
        **Syntax:** **to_ids=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to search only attributes with the flag
         "to_ids" set to true.''',
        require=False, validate=validators.Boolean())
    type = Option(
        doc='''
        **Syntax:** **type=***CSV string*
        **Description:**Comma(,)-separated string of types to search for.
         Wildcard is %.''',
        require=False)
    warning_list = Option(
        doc='''
        **Syntax:** **warning_list=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to filter out well known values.''',
        require=False, validate=validators.Boolean())

    @staticmethod
    def _record(serial_number, time_stamp, host, attributes, attribute_names, encoder):

        raw = encoder.encode(attributes)
        # Formulate record
        fields = dict()
        for f in attribute_names:
            if f in attributes:
                fields[f] = attributes[f]

        if serial_number > 0:
            fields['_serial'] = serial_number
            fields['_time'] = time_stamp
            fields['_raw'] = raw
            fields['host'] = host
            return fields

        record = OrderedDict(chain(
            (('_serial', serial_number), ('_time', time_stamp),
             ('_raw', raw), ('host', host)),
            map(lambda name: (name, fields.get(name, '')), attribute_names)))

        return record

    def generate(self):

        # Phase 1: Preparation
        my_args = prepare_config(self, 'misp42splunk')
        my_args['host'] = my_args['misp_url'].replace('https://', '')
        my_args['misp_url'] = my_args['misp_url'] + '/attributes/restSearch'

        # check that ONE of mandatory fields is present
        mandatory_arg = 0
        if self.json_request is not None:
            mandatory_arg = mandatory_arg + 1
        if self.eventid:
            mandatory_arg = mandatory_arg + 1
        if self.last:
            mandatory_arg = mandatory_arg + 1
        if self.date:
            mandatory_arg = mandatory_arg + 1

        if mandatory_arg == 0:
            logging.error('Missing "json_request", eventid", \
                "last" or "date" argument')
            raise Exception('Missing "json_request", "eventid", \
                "last" or "date" argument')
        elif mandatory_arg > 1:
            logging.error('Options "json_request", eventid", "last" \
                and "date" are mutually exclusive')
            raise Exception('Options "json_request", "eventid", "last" \
                and "date" are mutually exclusive')

        body_dict = dict()
        # Only ONE combination was provided
        if self.json_request is not None:
            body_dict = json.loads(self.json_request)
            logging.info('Option "json_request" set')
        elif self.eventid:
            if "," in self.eventid:
                event_criteria = {}
                event_list = self.eventid.split(",")
                event_criteria['OR'] = event_list
                body_dict['eventid'] = event_criteria
            else:
                body_dict['eventid'] = self.eventid
            logging.info('Option "eventid" set with %s',
                         json.dumps(body_dict['eventid']))
        elif self.last:
            body_dict['last'] = self.last
            logging.info('Option "last" set with %s', str(body_dict['last']))
        else:
            body_dict['date'] = self.date.split()
            logging.info('Option "date" set with %s',
                         json.dumps(body_dict['date']))

        # Force some values on JSON request
        body_dict['returnFormat'] = 'json'
        body_dict['withAttachments'] = False
        body_dict['deleted'] = False
        body_dict['includeEventUuid'] = True
        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['misp_key']
        headers['Accept'] = 'application/json'

        # Search pagination
        pagination = True
        if self.limit is not None:
            limit = int(self.limit)
        elif 'limit' in body_dict:
            limit = int(body_dict['limit'])
        else:
            limit = 1000
        if limit == 0:
            pagination = False
        if self.page is not None:
            page = int(self.page)
        elif 'page' in body_dict:
            page = body_dict['page']
        else:
            page = 1

        # Search parameters: boolean and filter
        if self.to_ids is True:
            body_dict['to_ids'] = True
            body_dict['enforceWarninglist'] = True  # protection
        elif self.to_ids is False:
            body_dict['to_ids'] = False
        if self.warning_list is True:
            body_dict['enforceWarninglist'] = True
        elif self.warning_list is False:
            body_dict['enforceWarninglist'] = False
        if self.geteventtag is True:
            body_dict['includeEventTags'] = True
        if self.category is not None:
            if "," in self.category:
                cat_criteria = {}
                cat_list = self.category.split(",")
                cat_criteria['OR'] = cat_list
                body_dict['category'] = cat_criteria
            else:
                body_dict['category'] = self.category
        if self.type is not None:
            if "," in self.type:
                type_criteria = {}
                type_list = self.type.split(",")
                type_criteria['OR'] = type_list
                body_dict['type'] = type_criteria
            else:
                body_dict['type'] = self.type
        if self.tags is not None or self.not_tags is not None:
            tags_criteria = {}
            if self.tags is not None:
                tags_list = self.tags.split(",")
                tags_criteria['OR'] = tags_list
            if self.not_tags is not None:
                tags_list = self.not_tags.split(",")
                tags_criteria['NOT'] = tags_list
            body_dict['tags'] = tags_criteria

        # output filter parameters
        if self.getuuid is True:
            my_args['getuuid'] = True
        else:
            my_args['getuuid'] = False
        if self.getorg is True:
            my_args['getorg'] = True
        else:
            my_args['getorg'] = False
        if self.pipesplit is True:
            my_args['pipe'] = True
        else:
            my_args['pipe'] = False
        if self.add_description is True:
            my_args['add_desc'] = True
        else:
            my_args['add_desc'] = False
        if self.output is not None:
            my_args['output'] = self.output
        else:
            my_args['output'] = "default"

        results = []
        # add colums for each type in results
        typelist = []

        if pagination is True:
            body_dict['page'] = page
            body_dict['limit'] = limit

        body = json.dumps(body_dict)
        logging.debug('mispgetioc request body: %s', body)
        # search
        r = requests.post(my_args['misp_url'], headers=headers, data=body,
                          verify=my_args['misp_verifycert'],
                          cert=my_args['client_cert_full_path'],
                          proxies=my_args['proxies'])
        # check if status is anything other than 200;
        # throw an exception if it is
        r.raise_for_status()
        # response is 200 by this point or we would have thrown an exception
        response = r.json()
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))
        if my_args['output'] == "raw":
            if 'response' in response:
                if 'Attribute' in response['response']:
                    attribute_names = []
                    serial_number = 0
                    for a in response['response']['Attribute']:
                        yield MispGetIocCommand._record(
                            serial_number, a['timestamp'], my_args['host'],
                            a, attribute_names, encoder)
                        serial_number += 1
                        GeneratingCommand.flush
        else:
            if 'response' in response:
                if 'Attribute' in response['response']:
                    for a in response['response']['Attribute']:
                        v = {}
                        v['misp_category'] = str(a['category'])
                        v['misp_attribute_id'] = str(a['id'])
                        v['misp_event_id'] = str(a['event_id'])
                        v['misp_timestamp'] = str(a['timestamp'])
                        v['misp_to_ids'] = str(a['to_ids'])
                        v['misp_comment'] = str(a['comment'])
                        tag_list = []
                        if 'Tag' in a:
                            for tag in a['Tag']:
                                try:
                                    tag_list.append(
                                        str(tag['name'])
                                    )
                                except Exception:
                                    pass
                        v['misp_tag'] = tag_list
                        # include ID of the organisation that
                        # created the attribute if requested
                        if 'Event' in a:
                            v['misp_event_uuid'] = str(a['Event']['uuid'])
                            if my_args['getorg']:
                                v['misp_orgc_id'] = str(a['Event']['orgc_id'])
                            if my_args['add_desc'] is True:
                                v['misp_event_info'] = str(a['Event']['info'])
                        # include attribute UUID if requested
                        if my_args['getuuid']:
                            v['misp_attribute_uuid'] = str(a['uuid'])
                        # handle object and multivalue attributes
                        v['misp_object_id'] = str(a['object_id'])
                        if my_args['add_desc'] is True:
                            if int(a['object_id']) == 0:
                                v['misp_description'] = 'MISP e' \
                                    + str(a['event_id']) + ' attribute ' \
                                    + str(a['uuid']) + ' of type "' \
                                    + str(a['type']) \
                                    + '" in category "' + str(a['category']) \
                                    + '" (to_ids:' + str(a['to_ids']) + ')'
                            else:
                                v['misp_description'] = 'MISP e' \
                                    + str(a['event_id']) + ' attribute ' \
                                    + str(a['uuid']) + ' of type "' \
                                    + str(a['type']) + '" in category "' \
                                    + str(a['category']) \
                                    + '" (to_ids:' + str(a['to_ids']) \
                                    + ' - o' + str(a['object_id']) + ' )'
                        current_type = str(a['type'])
                        # combined: not part of an object
                        # AND multivalue attribute AND to be split
                        # logging.debug('misp_event: %s', json.dumps(v))
                        if int(a['object_id']) == 0 and '|' in current_type \
                           and my_args['pipe'] is True:
                            mv_type_list = current_type.split('|')
                            mv_value_list = str(a['value']).split('|')
                            left_v = v.copy()
                            left_v['misp_type'] = mv_type_list.pop()
                            left_v['misp_value'] = mv_value_list.pop()
                            results.append(left_v)
                            if left_v['misp_type'] not in typelist:
                                typelist.append(left_v['misp_type'])
                            right_v = v.copy()
                            right_v['misp_type'] = mv_type_list.pop()
                            right_v['misp_value'] = mv_value_list.pop()
                            results.append(right_v)
                            if right_v['misp_type'] not in typelist:
                                typelist.append(right_v['misp_type'])
                        else:
                            v['misp_type'] = current_type
                            v['misp_value'] = str(a['value'])
                            results.append(v)
                            if current_type not in typelist:
                                typelist.append(current_type)

            logging.info(json.dumps(typelist))

            output_dict = {}
            # relevant_cat = ['Artifacts dropped', 'Financial fraud',
            # 'Network activity','Payload delivery','Payload installation']
            attribute_names = [
                'misp_attribute_id',
                'misp_attribute_uuid',
                'misp_category',
                'misp_comment',
                'misp_description',
                'misp_event_id',
                'misp_tag',
                'misp_timestamp',
                'misp_to_ids',
                'misp_type',
                'misp_value'
            ]
            for t in typelist:
                misp_t = 'misp_' + \
                    t.replace('-', '_').replace('|', '_p_')
                if misp_t not in attribute_names:
                    attribute_names.append(misp_t)
            for r in results:
                if int(r['misp_object_id']) == 0:  # not an object
                    key = str(r['misp_event_id']) + \
                        '_' + r['misp_attribute_id']
                    is_object_member = False
                else:  # this is a  MISP object
                    key = str(r['misp_event_id']) \
                        + '_object_' + str(r['misp_object_id'])
                    is_object_member = True
                if key not in output_dict:
                    v = dict(r)
                    for t in typelist:
                        misp_t = 'misp_' + t.replace('-', '_')\
                            .replace('|', '_p_')
                        v[misp_t] = []
                        if t == r['misp_type']:
                            v[misp_t].append(r['misp_value'])
                    v['misp_to_ids'] = []
                    v['misp_to_ids'].append(r['misp_to_ids'])
                    v['misp_category'] = []
                    v['misp_category'].append(r['misp_category'])
                    v['misp_attribute_id'] = []
                    v['misp_attribute_id']\
                        .append(r['misp_attribute_id'])
                    if my_args['getuuid'] is True:
                        v['misp_attribute_uuid'] = []
                        v['misp_attribute_uuid']\
                            .append(r['misp_attribute_uuid'])
                    if my_args['add_desc'] is True:
                        description = []
                        description.append(r['misp_description'])
                        v['misp_description'] = description
                    if is_object_member is True:
                        v['misp_type'] = 'misp_object'
                        v['misp_value'] = r['misp_object_id']
                    output_dict[key] = dict(v)
                else:
                    v = dict(output_dict[key])
                    misp_t = 'misp_' + r['misp_type'].replace('-', '_')
                    v[misp_t].append(r['misp_value'])  # set value for type
                    v['misp_to_ids'].append(r['misp_to_ids'])
                    v['misp_category'].append(r['misp_category'])
                    tag_list = v['misp_tag']
                    for tag in r['misp_tag']:
                        if tag not in tag_list:
                            tag_list.append(tag)
                    v['misp_tag'] = tag_list
                    if my_args['add_desc'] is True:
                        description = v['misp_description']
                        if r['misp_description'] not in description:
                            description.append(r['misp_description'])
                        v['misp_description'] = description
                    v['misp_attribute_id']\
                        .append(r['misp_attribute_id'])
                    if my_args['getuuid'] is True:
                        v['misp_attribute_uuid']\
                            .append(r['misp_attribute_uuid'])
                    if is_object_member is False:
                        misp_type = r['misp_type'] + '|' + v['misp_type']
                        v['misp_type'] = misp_type
                        misp_value = r['misp_value'] + '|' + v['misp_value']
                        v['misp_value'] = misp_value
                    output_dict[key] = dict(v)

            serial_number = 0
            logging.debug(json.dumps(attribute_names))
            for k, v in list(output_dict.items()):
                yield MispGetIocCommand._record(
                    serial_number, v['misp_timestamp'], my_args['host'],
                    v, attribute_names, encoder)
                serial_number += 1
                GeneratingCommand.flush


if __name__ == "__main__":
    # set up custom logger for the app commands
    logging.root
    loglevel = logging_level('misp42splunk')
    logging.root.setLevel(loglevel)
    logging.error('logging level is set to %s', loglevel)
    logging.error('PYTHON VERSION: ' + sys.version)
    dispatch(MispGetIocCommand, sys.argv, sys.stdin, sys.stdout, __name__)
