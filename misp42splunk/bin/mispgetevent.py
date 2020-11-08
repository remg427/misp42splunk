# coding=utf-8
#
# Extract IOC's from MISP
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#

from __future__ import absolute_import, division, print_function, unicode_literals
import misp42splunk_declare
from collections import OrderedDict
from itertools import chain
import json
import logging
from misp_common import prepare_config, logging_level
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
# from splunklib.searchcommands import splunklib_logger as logger
import sys
from splunklib.six.moves import map
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


def getattribute(a_item, type_list, pipesplit=False, object_id=0,
                 object_name="", object_comment=""):
    misp_a = dict()
    misp_a['misp_attribute_id'] = []
    misp_a['misp_attribute_id'].append(str(a_item['id']))
    misp_a['misp_attribute_uuid'] = []
    misp_a['misp_attribute_uuid'].append(str(a_item['uuid']))
    misp_a['misp_category'] = []
    misp_a['misp_category'].append(a_item['category'])
    misp_a['misp_to_ids'] = []
    misp_a['misp_to_ids'].append(str(a_item['to_ids']))
    misp_a['misp_comment'] = []
    misp_a['misp_comment'].append(str(a_item['comment']))
    misp_a['misp_attribute_timestamp'] = a_item['timestamp']
    misp_a['misp_attribute_sharing_group_id'] = str(a_item['sharing_group_id'])
    misp_a['misp_attribute_deleted'] = str(a_item['deleted'])
    misp_a['misp_object_id'] = object_id
    misp_a['misp_object_name'] = object_name
    misp_a['misp_object_comment'] = object_comment
    tag_list = []
    if 'Tag' in a_item:
        for tag in a_item['Tag']:
            try:
                tag_list.append(str(tag['name']))
            except Exception:
                pass
    misp_a['misp_attribute_tag'] = tag_list
    current_type = a_item['type']
    misp_a['misp_type'] = current_type
    misp_a['misp_value'] = str(a_item['value'])
    if current_type not in type_list:
        type_list.append(current_type)
    return misp_a


def init_misp_output(event_dict, attr_dict, attr_names):
    misp_out = dict(attr_dict)
    for name in attr_names:
        misp_out[name] = event_dict[name]
    return misp_out


def format_output_table(input_json, output_table, list_of_types,
                        getioc=False, pipesplit=False):
    if 'response' in input_json:
        columns = [
            'misp_analysis',
            'misp_attribute_count',
            'misp_distribution',
            'misp_event_date',
            'misp_event_id',
            'misp_event_info',
            'misp_event_published',
            'misp_event_uuid',
            'misp_extends_uuid',
            'misp_orgc_id',
            'misp_orgc_name',
            'misp_orgc_uuid',
            'misp_publish_timestamp',
            'misp_sharing_group_id',
            'misp_tag',
            'misp_threat_level',
            'misp_timestamp',
        ]
        for r_item in input_json['response']:
            if 'Event' in r_item:
                for a in list(r_item.values()):
                    v = dict()
                    v['misp_event_uuid'] = str(a['uuid'])
                    v['misp_event_id'] = str(a['id'])
                    v['misp_event_date'] = str(a['date'])
                    v['misp_timestamp'] = str(a['timestamp'])
                    v['misp_event_info'] = a['info']
                    v['misp_orgc_id'] = str(a['orgc_id'])
                    v['misp_attribute_count'] = str(a['attribute_count'])
                    v['misp_analysis'] = str(a['analysis'])
                    v['misp_threat_level'] = str(a['threat_level_id'])
                    v['misp_distribution'] = str(a['distribution'])
                    v['misp_sharing_group_id'] = str(a['sharing_group_id'])
                    v['misp_extends_uuid'] = str(a['extends_uuid'])
                    v['misp_event_published'] = str(a['published'])
                    v['misp_publish_timestamp'] = \
                        str(a['publish_timestamp'])
                    if 'Orgc' in a:
                        v['misp_orgc_name'] = str(a['Orgc']['name'])
                        v['misp_orgc_uuid'] = str(a['Orgc']['uuid'])
                    tag_list = []
                    if 'Tag' in a:
                        for tag in a['Tag']:
                            try:
                                tag_list.append(str(tag['name']))
                            except Exception:
                                pass
                    v['misp_tag'] = tag_list
                    v['misp_attribute_count'] = 0
                    if 'Attribute' in a:
                        v['misp_attribute_count'] = \
                            v['misp_attribute_count'] + len(a['Attribute'])
                        if getioc is True:
                            v['Attribute'] = list()
                            for attribute in a['Attribute']:
                                # combined: not part of an object AND
                                # multivalue attribute AND to be split
                                if int(attribute['object_id']) == 0 \
                                   and '|' in attribute['type'] \
                                   and pipesplit is True:
                                    mv_type_list = \
                                        attribute['type'].split('|')
                                    mv_value_list = \
                                        str(attribute['value']).split('|')
                                    left_a = attribute.copy()
                                    left_a['type'] = mv_type_list.pop()
                                    left_a['value'] = mv_value_list.pop()
                                    v['Attribute'].append(
                                        getattribute(left_a, list_of_types,
                                                     pipesplit,
                                                     left_a['object_id']))
                                    right_a = attribute.copy()
                                    right_a['type'] = mv_type_list.pop()
                                    right_a['value'] = mv_value_list.pop()
                                    v['Attribute'].append(
                                        getattribute(right_a, list_of_types,
                                                     pipesplit,
                                                     right_a['object_id']))
                                else:
                                    v['Attribute'].append(
                                        getattribute(attribute, list_of_types,
                                                     pipesplit,
                                                     attribute['object_id']))
                    if 'Object' in a:
                        for misp_o in a['Object']:
                            if 'Attribute' in misp_o:
                                v['misp_attribute_count'] = \
                                    v['misp_attribute_count'] \
                                    + len(misp_o['Attribute'])
                                if getioc is True:
                                    object_id = misp_o['id']
                                    object_name = misp_o['name']
                                    object_comment = misp_o['comment']
                                    for attribute in misp_o['Attribute']:
                                        v['Attribute'].append(
                                            getattribute(attribute,
                                                         list_of_types,
                                                         pipesplit,
                                                         object_id,
                                                         object_name,
                                                         object_comment))
                    logging.debug(
                        'event UUID is %s', str(v['misp_event_uuid']))
                    output_table.append(v)

        if output_table is not None:
            return columns

    return list()


@Configuration(retainsevents=False, type='reporting', distributed=False)
class MispGetEventCommand(GeneratingCommand):

    """ get the attributes from a MISP instance.
    ##Syntax
    .. code-block::
        | MispGetEventCommand misp_instance=<input> last=<int>(d|h|m)
        | MispGetEventCommand misp_instance=<input> event=<id1>(,<id2>,...)
        | MispGetEventCommand misp_instance=<input> date=<<YYYY-MM-DD>
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
    # status
        "tag": "optional",
        "searchall": "optional",
        "metadata": "optional",
        "published": "optional",
        "sgReferenceOnly": "optional",
        "eventinfo": "optional",
        "excludeLocalTags": "optional"

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
        "enforceWarninglist": not managed,
    }
    """
    # MANDATORY MISP instance for this search
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described
         in local/misp42splunk_instances.conf.''',
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
        **Description:**starting date. **eventid**, **last**
         and **date** are mutually exclusive''',
        require=False)
    # Other params
    category = Option(
        doc='''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for.
         Wildcard is %.''',
        require=False)
    getioc = Option(
        doc='''
        **Syntax:** **getioc=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return the list of attributes
         together with the event.''',
        require=False, validate=validators.Boolean())
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search; default 1000.
         0 = no pagination.''',
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
        **Description:**selection between a tabular or JSON output.''',
        require=False, validate=validators.Match("output", r"(default|raw)"))
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("page", r"^[0-9]+$"))
    pipesplit = Option(
        doc='''
        **Syntax:** **pipesplit=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to split multivalue attributes.''',
        require=False, validate=validators.Boolean())
    published = Option(
        doc='''
        **Syntax:** **published=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**select only published events (for option from to) .''',
        require=False, validate=validators.Boolean())
    tags = Option(
        doc='''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for.
         Wildcard is %.''',
        require=False)
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
    def _record(
            serial_number, time_stamp, host, attributes,
            attribute_names, encoder, condensed=False):

        if condensed is False:
            raw = encoder.encode(attributes)
        # Formulate record
        fields = dict()
        for f in attribute_names:
            if f in attributes:
                fields[f] = attributes[f]

        if serial_number > 0:
            fields['_serial'] = serial_number
            fields['_time'] = time_stamp
            if condensed is False:
                fields['_raw'] = raw
            fields['host'] = host
            return fields

        if condensed is False:
            record = OrderedDict(chain(
                (('_serial', serial_number), ('_time', time_stamp),
                 ('_raw', raw), ('host', host)),
                map(lambda name: (name, fields.get(name, '')), attribute_names)))
        else:
            record = OrderedDict(chain(
                (('_serial', serial_number), ('_time', time_stamp),
                 ('host', host)),
                map(lambda name: (name, fields.get(name, '')), attribute_names)))

        return record

    def generate(self):

        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if my_args is None:
            raise Exception("Sorry, no configuration for misp_instance={}".format(misp_instance))
        my_args['host'] = my_args['misp_url'].replace('https://', '')
        my_args['misp_url'] = my_args['misp_url'] + '/events/restSearch'

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
        if self.published is True:
            body_dict['published'] = True
        elif self.published is False:
            body_dict['published'] = False
        # Search parameters: boolean and filter
        # manage enforceWarninglist
        if self.warning_list is True:
            body_dict['enforceWarninglist'] = True
        elif self.warning_list is False:
            body_dict['enforceWarninglist'] = False
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
        if self.getioc is True:
            getioc = True
        else:
            getioc = False
        if self.pipesplit is True:
            pipesplit = True
        else:
            pipesplit = False
        if self.output is not None:
            output = self.output
        else:
            output = "default"

        if pagination is True:
            body_dict['page'] = page
            body_dict['limit'] = limit

        body = json.dumps(body_dict)
        logging.error('MispGetEventCommand request body: %s', body)
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
        if output == "raw":
            if 'response' in response:
                attribute_names = list()
                serial_number = 0
                for r_item in response['response']:
                    if 'Event' in r_item:
                        for e in r_item.values():
                            yield MispGetEventCommand._record(
                                serial_number, e['timestamp'], my_args['host'],
                                e, attribute_names, encoder)
                        serial_number += 1
                        GeneratingCommand.flush
        else:
            # build output table and list of types
            events = []
            typelist = []
            column_list = format_output_table(response, events, typelist,
                                              getioc, pipesplit)
            logging.info(
                'typelist containss %s values', str(len(typelist)))
            logging.debug(
                'typelist is %s', json.dumps(typelist))
            logging.info('results contains %s records', str(len(events)))

            if getioc is False:
                attribute_names = list()
                init_attribute_names = True
                serial_number = 0
                for e in events:
                    # logging.debug('event is %s', json.dumps(e))
                    if init_attribute_names is True:
                        for key in e.keys():
                            if key not in attribute_names:
                                attribute_names.append(key)
                        attribute_names.sort()
                        init_attribute_names = False
                        logging.debug(json.dumps(attribute_names))
                    yield MispGetEventCommand._record(
                        serial_number, e['misp_timestamp'],
                        my_args['host'], e, attribute_names, encoder, True)
                    serial_number += 1
                    GeneratingCommand.flush
            else:
                output_dict = {}
                for e in events:
                    if 'Attribute' in e:
                        for a in e['Attribute']:
                            if int(a['misp_object_id']) == 0:  # not an object
                                key = str(e['misp_event_id']) + '_' \
                                    + str(a['misp_attribute_id'])
                                is_object_member = False
                            else:  # this is a  MISP object
                                key = str(e['misp_event_id']) + \
                                    '_object_' + str(a['misp_object_id'])
                                is_object_member = True
                            if key not in output_dict:
                                v = init_misp_output(e, a, column_list)
                                for t in typelist:
                                    misp_t = 'misp_' \
                                        + t.replace('-', '_')\
                                             .replace('|', '_p_')
                                    v[misp_t] = []
                                    if t == a['misp_type']:
                                        v[misp_t].append(a['misp_value'])
                                if is_object_member is True:
                                    v['misp_type'] = v['misp_object_name']
                                    v['misp_value'] = v['misp_object_id']
                                output_dict[key] = dict(v)
                            else:
                                v = dict(output_dict[key])
                                misp_t = 'misp_' + a['misp_type']\
                                    .replace('-', '_').replace('|', '_p_')
                                v[misp_t].append(a['misp_value'])
                                if a['misp_to_ids'] not in v['misp_to_ids']:
                                    v['misp_to_ids'].append(a['misp_to_ids'])
                                if a['misp_category'] not in v['misp_category']:
                                    v['misp_category'].append(
                                        a['misp_category'])
                                v['misp_attribute_uuid']\
                                    .append(a['misp_attribute_uuid'])
                                v['misp_attribute_id']\
                                    .append(a['misp_attribute_id'])
                                if a['misp_attribute_tag'] is not None:
                                    a_tag = v['misp_attribute_tag']
                                    for t in a['misp_attribute_tag']:
                                        if t not in a_tag:
                                            a_tag.append(t)
                                    v['misp_attribute_tag'] = a_tag
                                if a['misp_comment'] not in v['misp_comment']:
                                    v['misp_comment'].append(a['misp_comment'])
                                if is_object_member is False:
                                    misp_type = a['misp_type'] \
                                        + '|' + v['misp_type']
                                    v['misp_type'] = misp_type
                                    misp_value = a['misp_value'] + \
                                        '|' + v['misp_value']
                                    v['misp_value'] = misp_value
                                output_dict[key] = dict(v)

                if output_dict is not None:
                    attribute_names = list()
                    init_attribute_names = True
                    serial_number = 0
                    for v in output_dict.values():
                        if init_attribute_names is True:
                            for key in v.keys():
                                if key not in attribute_names:
                                    attribute_names.append(key)
                            attribute_names.sort()
                            init_attribute_names = False
                            logging.debug(json.dumps(attribute_names))
                        yield MispGetEventCommand._record(
                            serial_number, v['misp_timestamp'],
                            my_args['host'], v, attribute_names, encoder, True)
                        serial_number += 1
                        GeneratingCommand.flush


if __name__ == "__main__":
    # set up custom logger for the app commands
    logging.root
    loglevel = logging_level('misp42splunk')
    logging.root.setLevel(loglevel)
    logging.error('logging level is set to %s', loglevel)
    logging.error('PYTHON VERSION: ' + sys.version)
    dispatch(MispGetEventCommand, sys.argv, sys.stdin, sys.stdout, __name__)
