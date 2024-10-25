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
from misp_common import prepare_config, generate_record, logging_level, urllib_init_pool, urllib_request

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.4.0"
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
        "attribute_timestamp": "optional",
        "enforceWarninglist": "optional",
        "to_ids": "optional",
        "deleted": "optional",
        "includeEventUuid": "optional",
        "includeEventTags": "optional",
        "event_timestamp": "optional",
        "threat_level_id": "optional",
        "eventinfo": "optional",
        "sharinggroup": "optional",
        "includeProposals": "optional",
        "includeDecayScore": "optional",
        "includeFullModel": "optional",
        "decayingModel": "optional",
        "excludeDecayed": "optional",
        "score": "optional",
        "first_seen": "optional",
        "last_seen": "optional"
    }
    # status
        "returnFormat": forced to json,
        "page": not managed,
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
        "publish_timestamp": param
        "timestamp": param,
        "attribute_timestamp": not managed,
        "enforceWarninglist": param,
        "to_ids": param,
        "deleted": param,
        "includeEventUuid": set to True,
        "includeEventTags": param,
        "event_timestamp":  not managed,
        "threat_level_id":  param
        "eventinfo": not managed,
        "includeProposals": not managed
        "includeDecayScore": param
        "includeFullModel": not managed,
        "decayingModel": param,
        "excludeDecayed": param,
        "score": param
        "first_seen": not managed
        "last_seen": not managed
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
        **Description:**Valid JSON request - see MISP REST API endpoint attributes/ restSearch''',
        require=False, validate=validators.Match("json_request", r"^{.+}$"))
    date = Option(
        doc='''
        **Syntax:** **date=***The user set event date field*
        **Description:**the user set date field at event level.
        The date format follows ISO 8061.''',
        require=False, validate=validators.Match("date", r"^[0-9\-,d]+$"))
    eventid = Option(
        doc='''
        **Syntax:** **eventid=***id1(,id2,...)*
        **Description:**list of event ID(s) or event UUID(s).''',
        require=False, validate=validators.Match("eventid", r"^[0-9a-f,\-]+$"))
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:** Events published within the last x amount of time, 
        where x can be defined in (d)ays, (h)ours, (m)inutes 
        (for example 5d or 12h or 30m), ISO 8601 datetime format or timestamp.
        **nota bene:** last is an alias of published_timestamp''',
        require=False, validate=validators.Match("last", r"^(\d+[hdm]|\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})$"))
    publish_timestamp = Option(
        doc='''
        **Syntax:** **publish_timestamp=***<int>d|h|m*
        **Description:** relative publication duration in day(s), hour(s) or minute(s).''',
        require=False, validate=validators.Match("last", r"^(\d+[hdm]|\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})$"))
    timestamp = Option(
        doc='''
        **Syntax:** **timestamp=***<int>d|h|m*
        **Description:** event timestamp (last change).''',
        require=False, validate=validators.Match("last", r"^(\d+[hdm]|\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})$"))
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
    decay_score_threshold = Option(
        doc='''
        **Syntax:** **decay_score_threshold=***<int>*
        **Description:**define the minimum sore to override on-the-fly the threshold of the decaying model.''',
        require=False, validate=validators.Match("decay_score_threshold", r"^[0-9]+$"))
    decaying_model = Option(
        doc='''
        **Syntax:** **decaying_model=***<int>*
        **Description:**ID of the decaying model to select specific model.''',
        require=False, validate=validators.Match("decaying_model", r"^[0-9]+$"))
    exclude_decayed = Option(
        doc='''
        **Syntax:** **exclude_decayed=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to exclude decayed attributes.''',
        require=False, validate=validators.Boolean(), default=False)
    expand_object = Option(
        doc='''
        **Syntax:** **gexpand_object=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to have object attributes expanded (one per line).
        By default, attributes of one object are displayed on same line.
        ''',
        require=False, 
        default=False,
        validate=validators.Boolean())
    geteventtag = Option(
        doc='''
        **Syntax:** **geteventtag=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean includeEventTags. By default only
         attribute tag(s) are returned.''',
        require=False, validate=validators.Boolean())
    include_decay_score = Option(
        doc='''
        **Syntax:** **include_decay_score=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return decay sores.''',
        require=False, validate=validators.Boolean(), default=False)
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
        **Syntax:** **output=***<fields|json>*
        **Description:**Selection between the default Splunk tabular view - output=fields - or JSON - output=json.
        ''',
        require=False,
        default='fields', 
        validate=validators.Match("output", r"(fields|json)"))
    pipesplit = Option(
        doc='''
        **Syntax:** **pipesplit=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to split multivalue attributes.
        ''',
        require=False, 
        default=True, 
        validate=validators.Boolean())
    tags = Option(
        doc='''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for.
         Wildcard is %.''',
        require=False)
    threat_level_id = Option(
        doc='''
        **Syntax:** **threat_level_id=***<int>*
        **Description:**define the threat level (1-High, 2-Medium, 3-Low, 4-Undefined).''',
        require=False, validate=validators.Match("limit", r"^[1-4]$"))
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
        logging.error('[IO-201] logging level is set to %s', loglevel)
        logging.error('[IO-202] PYTHON VERSION: ' + sys.version)

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
            raise Exception("[IO-101] Sorry, no configuration for misp_instance={}".format(misp_instance))
        my_args['host'] = my_args['misp_url'].replace('https://', '')
        my_args['misp_url'] = my_args['misp_url'] + '/attributes/restSearch'

        # check that ONE of mandatory fields is present
        mandatory_arg = 0
        if self.date:
            mandatory_arg = mandatory_arg + 1
        if self.eventid:
            mandatory_arg = mandatory_arg + 1
        if self.json_request is not None:
            mandatory_arg = mandatory_arg + 1
        if self.last:
            mandatory_arg = mandatory_arg + 1
        if self.publish_timestamp:
            mandatory_arg = mandatory_arg + 1
        if self.timestamp:
            mandatory_arg = mandatory_arg + 1

        if mandatory_arg == 0:
            self.log_error('[IO-102] Missing "date", "eventid", "json_request", "last", "publish_timestamp" or "timestamp" argument')
            raise Exception('[IO-102] Missing "date", "eventid", "json_request", "last", "publish_timestamp" or "timestamp" argument')
        elif mandatory_arg > 1:
            self.log_error('[IO-103] Options "date", "eventid", "json_request", "last", "publish_timestamp" and "timestamp" are mutually exclusive')
            raise Exception('[IO-103] Options "date", "eventid", "json_request", "last", "publish_timestamp" and "timestamp" are mutually exclusive')

        body_dict = dict()
        # Only ONE combination was provided
        if self.json_request is not None:
            body_dict = json.loads(self.json_request)
            self.log_info('[IO-104] Option "json_request" set')
        elif self.eventid:
            if "," in self.eventid:
                event_criteria = {}
                event_list = self.eventid.split(",")
                event_criteria['OR'] = event_list
                body_dict['eventid'] = event_criteria
            else:
                body_dict['eventid'] = self.eventid
            self.log_info('[IO-105] Option "eventid" set with {}'
                          .format(json.dumps(body_dict['eventid'])))
        elif self.last:
            body_dict['last'] = self.last
            self.log_info('[IO-106] Option "last" set with {}'
                          .format(body_dict['last']))
        elif self.publish_timestamp:
            body_dict['publish_timestamp'] = self.publish_timestamp
            self.log_info('[IO-107] Option "publish_timestamp" set with {}'
                          .format(body_dict['publish_timestamp']))
        elif self.timestamp:
            body_dict['timestamp'] = self.timestamp
            self.log_info('[IO-108] Option "timestamp" set with {}'
                          .format(body_dict['timestamp']))
        else:  # implicit param date
            if "," in self.date:  # string should contain a range
                date_list = self.date.split(",")
                body_dict['date'] = [str(date_list[0]), str(date_list[1])]
            else:
                body_dict['date'] = self.date
            self.log_info('[IO-109] Option "date range" key date {}'
                          .format(json.dumps(body_dict['date'])))

        # Force some values on JSON request
        body_dict['returnFormat'] = 'json'
        body_dict['withAttachments'] = False
        body_dict['includeEventUuid'] = True

        # Search pagination
        if 'page' in body_dict:
            page = body_dict['page']
        else:
            page = 0

        if 'limit' in body_dict:
            limit = int(body_dict['limit'])
        elif self.limit is not None:
            limit = int(self.limit)
        else:
            limit = 1000
        body_dict['limit'] = limit
        if limit == 0:
            body_dict.pop('page', None)

        self.log_debug('[IO-201] limit {} page {}'
            .format(limit,page))


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
                types = self.type.split(",")
                type_criteria['OR'] = types
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
        if self.threat_level_id is not None:
            body_dict['threat_level_id'] = self.threat_level_id

        # Decaying Model related Search parameters
        if self.include_decay_score is True:
            body_dict['includeDecayScore'] = True
        if self.exclude_decayed is True:
            body_dict['excludeDecayed'] = True
        if self.decaying_model:
            body_dict['decayingModel'] = self.decaying_model
        if self.decay_score_threshold:
            body_dict['score'] = self.decay_score_threshold        

        # output filter parameters
        if self.add_description is True:
            my_args['add_description'] = True
        else:
            my_args['add_description'] = False
        if self.expand_object is True:
            my_args['expand_object'] = True
        else:
            my_args['expand_object'] = False
        if self.pipesplit is False:
            my_args['pipesplit'] = False
        else:
            my_args['pipesplit'] = True
        if self.output is not None:
            my_args['output'] = self.output
        else:
            my_args['output'] = "fields"

        connection, connection_status = urllib_init_pool(self, my_args)
        if connection:
            if page == 0 and limit != 0:
                request_loop = True
                body_dict['page'] = 1
                response = {'response': {'Attribute': []}}
                while request_loop:
                    iter_response = urllib_request(
                        self,
                        connection,
                        'POST',
                        my_args['misp_url'],
                        body_dict,
                        my_args)
                    if 'response' in iter_response:
                        if 'Attribute' in iter_response['response']:
                            rlength = len(
                                iter_response['response']['Attribute'])
                            if rlength != 0:
                                response['response']['Attribute'].extend(
                                    iter_response['response']['Attribute'])
                                self.log_debug(
                                    '[IO-202] request on page {} returned {} attribute(s); querying next page'
                                    .format(body_dict['page'],rlength))
                                body_dict['page'] = body_dict['page'] + 1
                            else:
                                # last page is reached
                                request_loop = False
                        else:
                            request_loop = False
                    else:
                        request_loop = False
            else:
                response = urllib_request(
                    self,
                    connection,
                    'POST',
                    my_args['misp_url'],
                    body_dict,
                    my_args)
        else:
            response = connection_status

        self.log_info(
            '[IO-203] response contains {} records'.format(len(response)))

        if "_raw" in response:
            yield response
        else: 
            # response_dict contains results
            attribute_list = response['response'].get('Attribute', [])
            encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))

            # if output=json, returns JSON objects
            if my_args['output'] == "json":
                for a in attribute_list:
                    splunk_ts = a['timestamp']
                    yield generate_record(
                        a,
                        splunk_ts,
                        self
                    )

            # default output=fields: extract some values from JSON attributes
            else:
                results = []
                prefix = "misp_"
                misp_type_list = list()
                attribute_mapping = {
                    'category': 'category',
                    'comment': 'comment',
                    'deleted': 'deleted',
                    'distribution': 'attribute_distribution',
                    'event_id': 'event_id',
                    'event_uuid': 'event_uuid',
                    'first_seen': 'first_seen',
                    'id': 'attribute_id',
                    'last_seen': 'last_seen',
                    'object_id': 'object_id',
                    'object_relation': 'object_relation',
                    'sharing_group_id': 'sharing_group_id',
                    'timestamp': 'timestamp',
                    'to_ids': 'to_ids',
                    'type': 'type',
                    'uuid': 'attribute_uuid',
                    'value': 'value',
                }
                for a in attribute_list:
                    attribute = dict()
                    splunk_ts = a['timestamp']
                    for key, value in attribute_mapping.items():
                        if key in a:
                            attribute[f'{prefix}{value}'] = a[key]
                    if 'Event' in a:
                        e = a['Event']
                        event_mapping = {
                            'distribution': 'event_distribution',
                            'id': 'event_id',
                            'info': 'event_info',
                            'org_id': 'org_id',
                            'orgc_id': 'orgc_id',
                            'publish_timestamp': 'publish_timestamp',
                            'uuid': 'event_uuid',
                        } 
                        for key, value in event_mapping.items():
                            if key in e:
                                attribute[f'{prefix}{value}'] = e[key]

                    if 'Tag' in a:
                        attribute[f'{prefix}tag'] = list()
                        if isinstance(a['Tag'], list):
                            for tag in a.get('Tag', []):
                                attribute[f'{prefix}tag'].append(tag['name'].strip())
                        elif isinstance(a['Tag'], dict):
                            attribute[f'{prefix}tag'].append(a['Tag']['name'].strip())

                    # add description sttring
                    if my_args['add_description'] is True:
                        if int(attribute['misp_object_id']) == 0:
                            attribute['misp_description'] = 'MISP event:' \
                                + str(attribute['misp_event_uuid']) + ' attribute:' \
                                + str(attribute['misp_attribute_uuid']) + ' of type "' \
                                + str(attribute['misp_type']) \
                                + '" in category "' + str(attribute['misp_category']) \
                                + '" (to_ids:' + str(attribute['misp_to_ids']) + ')'
                        else:
                            attribute['misp_description'] = 'MISP event:' \
                                + str(attribute['misp_event_uuid']) + ' attribute:' \
                                + str(attribute['misp_attribute_uuid']) + ' of type "' \
                                + str(attribute['misp_type']) \
                                + '" in category "' + str(attribute['misp_category']) \
                                + '" (to_ids:' + str(attribute['misp_to_ids']) \
                                + ' - object_id:' + str(attribute['misp_object_id']) \
                                + ' object_relation:' + str(attribute['misp_object_relation']) + ')'

                    # combined: not part of an object
                    # AND multivalue attribute AND to be split
                    if int(a['object_id']) == 0 \
                       and '|' in a['type'] \
                       and my_args['pipesplit'] is True:
                        mv_type_list = str(a['type']).split('|')
                        mv_value_list = str(a['value']).split('|')
                        left_v = attribute.copy()
                        left_v['misp_type'] = str(mv_type_list.pop())
                        left_v['misp_value'] = str(mv_value_list.pop())
                        results.append(left_v)
                        if left_v['misp_type'] not in misp_type_list:
                            misp_type_list.append(left_v['misp_type'])
                        right_v = attribute.copy()
                        right_v['misp_type'] = str(mv_type_list.pop())
                        right_v['misp_value'] = str(mv_value_list.pop())
                        results.append(right_v)
                        if right_v['misp_type'] not in misp_type_list:
                            misp_type_list.append(right_v['misp_type'])
                    else:
                        results.append(attribute)
                        if attribute['misp_type'] not in misp_type_list:
                            misp_type_list.append(attribute['misp_type'])
                self.log_info(json.dumps(misp_type_list))

                # consolidate attribute values under output table
                output_dict = {}
                for r in results:
                    if my_args['expand_object'] is False \
                       and int(r['misp_object_id']) != 0:
                        r_key = str(r['misp_event_id']) \
                            + '_object_' + str(r['misp_object_id'])
                    else:
                        r_key = str(r['misp_event_id']) + \
                            '_' + str(r['misp_attribute_id'])

                    if r_key not in output_dict:
                        v = dict(r)
                        for t in misp_type_list:
                            misp_t = prefix + t.replace('-', '_').replace('|','_p_')
                            v[misp_t] = list()
                            if t == r['misp_type']:
                                v[misp_t].append(r['misp_value'])
                        output_dict[r_key] = dict(v)
                    else:
                        v = dict(output_dict[r_key])
                        if v['misp_object_id'] == 0:  # this is a composed attribute
                            misp_t = prefix + r['misp_type'].replace('-', '_').replace('|','_p_')
                            v[misp_t].append(r['misp_value'])  # set value for type
                            composed_misp_type = list(r['misp_type'].replace('_', '-') \
                                                    + '|' \
                                                    + v['misp_type'].replace('_', '-'))
                            v['misp_type'] = composed_misp_type
                            composed_misp_value = list(str(r['misp_value']) + '|' + str(v['misp_value']))
                            v['misp_value'] = composed_misp_value
                        else:  # object to merge
                            misp_t = 'misp_' + r['misp_type'].replace('-', '_')
                            v[misp_t].append(r['misp_value'])  # set value for type

                            for orig_key, misp_key in attribute_mapping.items():
                                misp_key = prefix + misp_key
                                if misp_key in r:
                                    if misp_key in v:
                                        if not isinstance(v[misp_key], list):
                                            misp_key_list = list()
                                            misp_key_list.append(v[misp_key])
                                            v[misp_key] = misp_key_list
                                        if r[misp_key] not in v[misp_key]:
                                            v[misp_key].append(r[misp_key]) 
                                    else:
                                        v[misp_key] = r[misp_key]

                            tag_list = v['misp_tag']
                            for tag in r['misp_tag']:
                                if tag not in tag_list:
                                    tag_list.append(tag)
                            v['misp_tag'] = tag_list
                            
                        output_dict[r_key] = dict(v)

                for r_key, result in output_dict.items():
                    if isinstance(result['misp_timestamp'], list):
                        splunk_ts = 999999999999
                        for ts in result['misp_timestamp']:
                            if int(ts) < splunk_ts:
                                splunk_ts = int(ts)
                    else:
                        splunk_ts = int(result['misp_timestamp'])

                    yield generate_record(
                        result,
                        splunk_ts,
                        self
                    )    

if __name__ == "__main__":
    dispatch(MispGetIocCommand, sys.argv, sys.stdin, sys.stdout, __name__)
