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
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
from splunklib.six.moves import map
from collections import OrderedDict
from itertools import chain
import sys
import json
import logging
from misp_common import prepare_config, logging_level, urllib_init_pool, urllib_request

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.2.1"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(distributed=False)
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
        as described in local/misp42splunk_instances.conf.''',
        require=True)
    # MANDATORY: json_request XOR eventid XOR last XOR date
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False, validate=validators.Match("json_request", r"^{.+}$"))
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
        **Description:**the user set date field on event level.
        The date format follows ISO 8061.
        **eventid**, **last** and **date** are mutually exclusive''',
        require=False, validate=validators.Match("date", r"^[0-9\-,d]+$"))
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
    expand_object = Option(
        doc='''
        **Syntax:** **gexpand_object=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to have object attributes expanded (one per line).
        By default, attributes of one object are displayed on same line.''',
        require=False, validate=validators.Boolean())
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
    include_deleted = Option(
        doc='''
        **Syntax:** **include_deleted=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean include£_deleted. By default only noon deleted
        attribute are returned.''',
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
        **Description:**selection between the default behaviou or JSON output by attribute.''',
        require=False, validate=validators.Match(
            "output", r"(default|raw)"))
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
        logging.error('[IO-101] logging level is set to %s', loglevel)
        logging.error('[IO-102] PYTHON VERSION: ' + sys.version)

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
        # loggging
        self.set_log_level()
        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if my_args is None:
            raise Exception("Sorry, no configuration for misp_instance={}".format(misp_instance))
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
            self.log_error('Missing "json_request", "eventid", "last" or "date" argument')
            raise Exception('Missing "json_request", "eventid", "last" or "date" argument')
        elif mandatory_arg > 1:
            self.log_error('Options "json_request", "eventid", "last" and "date" are mutually exclusive')
            raise Exception('Options "json_request", "eventid", "last" and "date" are mutually exclusive')

        body_dict = dict()
        # Only ONE combination was provided
        if self.json_request is not None:
            body_dict = json.loads(self.json_request)
            self.log_info('Option "json_request" set')
        elif self.eventid:
            if "," in self.eventid:
                event_criteria = {}
                event_list = self.eventid.split(",")
                event_criteria['OR'] = event_list
                body_dict['eventid'] = event_criteria
            else:
                body_dict['eventid'] = self.eventid
            self.log_info('Option "eventid" set with {}'
                          .format(json.dumps(body_dict['eventid'])))
        elif self.last:
            body_dict['last'] = self.last
            self.log_info('Option "last" set with {}'
                          .format(body_dict['last']))
        else:  # implicit param date
            if "," in self.date:  # string should contain a range
                date_list = self.date.split(",")
                body_dict['date'] = [str(date_list[0]), str(date_list[1])]
            else:
                body_dict['date'] = self.date
            self.log_info('Option "date range" key date {}'
                          .format(json.dumps(body_dict['date'])))

        # Force some values on JSON request
        body_dict['returnFormat'] = 'json'
        body_dict['withAttachments'] = False
        body_dict['includeEventUuid'] = True

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
        # manage to_ids and enforceWarninglist
        # to avoid FP enforceWarninglist is set to True if
        # to_ids is set to True (search criterion)
        if self.include_deleted is True:
            body_dict['deleted'] = True
        else:
            body_dict['deleted'] = False
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
        if self.add_description is True:
            my_args['add_desc'] = True
        else:
            my_args['add_desc'] = False
        if self.expand_object is True:
            my_args['expand'] = True
        else:
            my_args['expand'] = False
        if self.getorg is True:
            my_args['getorg'] = True
        else:
            my_args['getorg'] = False
        if self.getuuid is True:
            my_args['getuuid'] = True
        else:
            my_args['getuuid'] = False
        if self.pipesplit is True:
            my_args['pipe'] = True
        else:
            my_args['pipe'] = False
        if self.output is not None:
            my_args['output'] = self.output
        else:
            my_args['output'] = "default"

        # add colums for each type in results
        results = []
        typelist = []
        if pagination is True:
            body_dict['page'] = page
            body_dict['limit'] = limit

        connection, connection_status = urllib_init_pool(self, my_args)
        if connection:
            response = urllib_request(self, connection, 'POST', my_args['misp_url'], body_dict, my_args)
        else:
            response = connection_status

        if "_raw" in response:
            yield response
        else:  
            encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))
            # if raw output, returns JSON object
            if 'response' in response:
                if 'Attribute' in response['response']:
                    if my_args['output'] == "raw":
                        attribute_names = list()
                        serial_number = 0
                        for a in response['response']['Attribute']:
                            yield MispGetIocCommand._record(
                                serial_number, a['timestamp'], my_args['host'],
                                a, attribute_names, encoder)
                            serial_number += 1
                            GeneratingCommand.flush
            # default output: extract some values from JSON attributes
                    else:
                        common_columns = ["category", "to_ids", "timestamp", "comment",
                                          "sharing_group_id", "deleted", "disable_correlation",
                                          "first_seen", "last_seen", "object_id", "object_relation",
                                          "type", "value"]
                        attribute_specific_columns = ["id", "distribution"]
                        if my_args['getuuid']:
                            attribute_specific_columns.append("uuid")
                        for a in response['response']['Attribute']:
                            v = {}
                            # prepend key names with misp_attribute_
                            for asc in attribute_specific_columns:
                                misp_asc = "misp_attribute_" + asc
                                if asc in a:
                                    v[misp_asc] = str(a[asc])
                            # prepend key names with misp_
                            for cc in common_columns:
                                misp_cc = "misp_" + cc
                                if cc in a:
                                    v[misp_cc] = str(a[cc])
                            # append attribute tags to tag list
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
                            
                            # include Event metatdata
                            if 'Event' in a:
                                attr_event_columns = ["id", "uuid", "distribution", "info"]
                                for aec in attr_event_columns:
                                    misp_aec = "misp_event_" + aec
                                    if aec in a['Event']:
                                        v[misp_aec] = str(a['Event'][aec])
                                if my_args['getorg'] is True:
                                    attr_org_columns = ["org_id", "orgc_id"]
                                    for aoc in attr_org_columns:
                                        misp_aoc = "misp_" + aoc
                                        if aoc in a['Event']:
                                            v[misp_aoc] = str(a['Event'][aoc])
                                
                            # add description sttring
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
                            if int(a['object_id']) == 0 and '|' in current_type \
                               and my_args['pipe'] is True:
                                mv_type_list = current_type.split('|')
                                mv_value_list = str(a['value']).split('|')
                                left_v = v.copy()
                                left_v['misp_type'] = str(mv_type_list.pop())
                                left_v['misp_value'] = str(mv_value_list.pop())
                                results.append(left_v)
                                if left_v['misp_type'] not in typelist:
                                    typelist.append(left_v['misp_type'])
                                right_v = v.copy()
                                right_v['misp_type'] = str(mv_type_list.pop())
                                right_v['misp_value'] = str(mv_value_list.pop())
                                results.append(right_v)
                                if right_v['misp_type'] not in typelist:
                                    typelist.append(right_v['misp_type'])
                            else:
                                results.append(v)
                                if current_type not in typelist:
                                    typelist.append(current_type)

                self.log_info(json.dumps(typelist))

                # consolidate attribute values under output table
                output_dict = {}
                if my_args['expand'] is True:
                    for r in results:
                        key = str(r['misp_event_id']) + \
                            '_' + str(r['misp_attribute_id'])
                        if key not in output_dict:
                            v = dict(r)
                            for t in typelist:
                                misp_t = 'misp_' + t.replace('-', '_').replace('|', '_p_')
                                v[misp_t] = []
                                if t == r['misp_type']:
                                    v[misp_t].append(r['misp_value'])
                            output_dict[key] = dict(v)
                        else:
                            v = dict(output_dict[key])
                            misp_t = 'misp_' + r['misp_type'].replace('-', '_').replace('|', '_p_')
                            v[misp_t].append(r['misp_value'])  # set value for type
                            misp_type = r['misp_type'] + '|' + v['misp_type']
                            v['misp_type'] = list()
                            v['misp_type'].append(misp_type)
                            misp_value = str(r['misp_value']) + '|' + str(v['misp_value'])
                            v['misp_value'] = list()
                            v['misp_value'].append(misp_value)
                            output_dict[key] = dict(v)
                else:
                    for r in results:
                        if int(r['misp_object_id']) == 0:  # not an object
                            key = str(r['misp_event_id']) + \
                                '_' + str(r['misp_attribute_id'])
                            is_object_member = False
                        else:  # this is a  MISP object
                            key = str(r['misp_event_id']) \
                                + '_object_' + str(r['misp_object_id'])
                            is_object_member = True
                        if key not in output_dict:
                            v = dict(r)
                            for t in typelist:
                                misp_t = 'misp_' + t.replace('-', '_').replace('|', '_p_')
                                v[misp_t] = list()
                                if t == r['misp_type']:
                                    v[misp_t].append(r['misp_value'])
                            for ac in common_columns:
                                misp_ac = "misp_" + ac
                                if misp_ac in r:
                                    v[misp_ac] = list()
                                    v[misp_ac].append(str(r[misp_ac]))
                            v['misp_attribute_id'] = list()
                            v['misp_attribute_id'].append(r['misp_attribute_id'])
                            if my_args['getuuid'] is True:
                                v['misp_attribute_uuid'] = list()
                                v['misp_attribute_uuid'].append(r['misp_attribute_uuid'])
                            if my_args['add_desc'] is True:
                                v['misp_description'] = list()
                                v['misp_description'].append(r['misp_description'])
                            output_dict[key] = dict(v)
                        else:
                            v = dict(output_dict[key])
                            misp_t = 'misp_' + r['misp_type'].replace('-', '_').replace('|', '_p_')
                            v[misp_t].append(r['misp_value'])  # set value for type
                            for ac in common_columns:
                                misp_ac = "misp_" + ac
                                if misp_ac in r:
                                    if misp_ac not in v:
                                        v[misp_ac] = list()
                                    v[misp_ac].append(str(r[misp_ac]))
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
                            if is_object_member is False:
                                if r['misp_attribute_id'] not in v['misp_attribute_id']:
                                    v['misp_attribute_id'].append(r['misp_attribute_id'])
                                if my_args['getuuid'] is True:
                                    if r['misp_attribute_uuid'] not in v['misp_attribute_uuid']:
                                        v['misp_attribute_uuid'].append(r['misp_attribute_uuid'])
                                misp_type = []  # composed attribute
                                misp_type.append(r['misp_type'] + '|' + v['misp_type'][0])
                                v['misp_type'] = misp_type
                                misp_value = []
                                misp_value.append(str(r['misp_value']) + '|' + str(v['misp_value'][0]))
                                v['misp_value'] = misp_value
                            else:
                                v['misp_attribute_id'].append(r['misp_attribute_id'])
                                if my_args['getuuid'] is True:
                                    v['misp_attribute_uuid'].append(r['misp_attribute_uuid'])
                            output_dict[key] = dict(v)

                # return output table
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

                    if isinstance(v['misp_timestamp'], list):
                        timestamp = 999999999999
                        for ts in v['misp_timestamp']:
                            if int(ts) < timestamp:
                                timestamp = int(ts)
                    else:
                        timestamp = int(v['misp_timestamp'])

                    yield MispGetIocCommand._record(
                        serial_number, timestamp, my_args['host'],
                        v, attribute_names, encoder, True)
                    serial_number += 1
                    GeneratingCommand.flush


if __name__ == "__main__":
    dispatch(MispGetIocCommand, sys.argv, sys.stdin, sys.stdout, __name__)
