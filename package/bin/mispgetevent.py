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
from misp_common import prepare_config, logging_level, urllib_init_pool, urllib_request
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import os
from splunklib.six.moves import map
import sys

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome
                                  + "/var/log/splunk/misp42splunk.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s \
                              %(funcName)s %(lineno)d %(message)s')
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr,logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)      # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.3.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


def getattribute(a_item, pipesplit=False, object_data={}):
    common_columns = ["category", "to_ids", "comment", "type", "value"]
    attribute_specific_columns = ["id", "uuid", "deleted", "distribution",
                                  "first_seen", "last_seen", "object_relation",
                                  "sharing_group_id", "timestamp"]
    misp_a = dict()
    # prepend key names with misp_attribute_
    for asc in attribute_specific_columns:
        misp_asc = "misp_attribute_" + asc
        misp_a[misp_asc] = str(a_item[asc])
    # prepend key names with misp_
    for cc in common_columns:
        misp_cc = "misp_" + cc
        misp_a[misp_cc] = str(a_item[cc])

    tag_list = list()
    if 'Tag' in a_item:
        tags = a_item['Tag']
        for tag in tags:
            if tag not in tag_list:
                tag_list.append(str(tag['name']))
    misp_a['misp_attribute_tag'] = tag_list

    if len(object_data) > 0:
        misp_a.update(object_data)

    return misp_a


def get_attribute_columns():
    object_columns = ["comment", "deleted", "description", "distribution",
                      "first_seen", "id", "last_seen", "name", "meta-category",
                      "sharing_group_id", "template_uuid", "template_version",
                      "timestamp", "uuid"]
    common_columns = ["category", "to_ids", "comment", "type", "value"]
    attribute_specific_columns = ["id", "uuid", "deleted", "distribution",
                                  "first_seen", "last_seen", "object_relation",
                                  "sharing_group_id", "timestamp"]
    attribute_columns = list()

    # prepend key names with misp_object_
    for obj in object_columns:
        misp_obj = "misp_object_" + obj
        attribute_columns.append(misp_obj)

    # prepend key names with misp_attribute_
    for asc in attribute_specific_columns:
        misp_asc = "misp_attribute_" + asc
        attribute_columns.append(misp_asc)
    attribute_columns.append("misp_attribute_tag")

    # prepend key names with misp_
    for cc in common_columns:
        misp_cc = "misp_" + cc
        attribute_columns.append(misp_cc)

    return attribute_columns


def init_misp_output(event_dict, attr_dict, attr_column_names):
    misp_out = dict(event_dict)
    misp_out.pop('Attribute', None)
    for name in attr_column_names:
        if name in attr_dict:
            misp_out[name] = str(attr_dict[name])
    return misp_out


def format_output_table(input_json, output_table, list_of_types,
                        getioc=False, pipesplit=False, only_to_ids=False):
    # process events and return a list of dict
    # if getioc=true each event entry contains a key Attribute
    # with a list of all attributes
    if 'response' in input_json:
        common_columns = ["analysis", "attribute_count", "disable_correlation",
                          "distribution", "extends_uuid", "locked",
                          "proposal_email_lock", "publish_timestamp",
                          "sharing_group_id", "threat_level_id", "timestamp"]
        event_specific_columns = ["id", "date", "info", "published", "uuid"]
        organisation_columns = ["id", "name", "uuid", "local"]
        object_columns = ["comment", "deleted", "description", "distribution",
                          "first_seen", "id", "last_seen", "name",
                          "meta-category", "sharing_group_id", "template_uuid",
                          "template_version", "timestamp", "uuid"]
        for r_item in input_json['response']:
            if 'Event' in r_item:
                for a in list(r_item.values()):
                    v = dict()
                    # prepend key names with misp_event_
                    for esc in event_specific_columns:
                        misp_esc = "misp_event_" + esc
                        v[misp_esc] = str(a[esc])
                    # prepend key names with misp_
                    for cc in common_columns:
                        misp_cc = "misp_" + cc
                        v[misp_cc] = str(a[cc])
                    if 'Org' in a:
                        # prepend key names with misp_org_
                        for oc in organisation_columns:
                            misp_oc = "misp_org_" + oc
                            v[misp_oc] = str(a['Org'][oc])
                    if 'Orgc' in a:
                        # prepend key names with misp_org_
                        for oc in organisation_columns:
                            misp_oc = "misp_orgc_" + oc
                            v[misp_oc] = str(a['Orgc'][oc])
                    # append attribute tags to tag list
                    tag_list = []
                    if 'Tag' in a:
                        for tag in a['Tag']:
                            try:
                                tag_list.append(str(tag['name']))
                            except Exception:
                                pass
                    v['misp_tag'] = tag_list
                    if getioc is True:
                        v['Attribute'] = list()
                        if 'Object' in a:
                            for misp_o in a['Object']:
                                object_dict = dict()
                                for obj in object_columns:
                                    # prepend key names with misp_object_
                                    misp_obj = "misp_object_" + obj
                                    if obj in misp_o:
                                        object_dict[misp_obj] = misp_o[obj]
                                    else:
                                        object_dict[misp_obj] = ""
                                if 'Attribute' in misp_o:
                                    for attribute in misp_o['Attribute']:
                                        keep_attribute = True
                                        if only_to_ids is True:
                                            if attribute['to_ids'] is True:
                                                keep_attribute = True
                                            else:
                                                keep_attribute = False
                                        if keep_attribute is True:
                                            if attribute['type'] not in list_of_types:
                                                list_of_types.append(attribute['type'])
                                            v['Attribute'].append(
                                                getattribute(attribute,
                                                             pipesplit,
                                                             object_dict))

                        if 'Attribute' in a:
                            object_dict = dict()
                            for obj in object_columns:
                                misp_obj = "misp_object_" + obj
                                object_dict[misp_obj] = ""
                            object_dict['misp_object_id'] = 0
                            for attribute in a['Attribute']:
                                # combined: not part of an object AND
                                # multivalue attribute AND to be split
                                keep_attribute = True
                                if only_to_ids is True:
                                    if attribute['to_ids'] is True:
                                        keep_attribute = True
                                    else:
                                        keep_attribute = False
                                if keep_attribute is True:
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
                                        if left_a['type'] not in list_of_types:
                                            list_of_types.append(left_a['type'])
                                        v['Attribute'].append(
                                            getattribute(left_a, 
                                                         pipesplit,
                                                         object_dict))
                                        right_a = attribute.copy()
                                        right_a['type'] = mv_type_list.pop()
                                        right_a['value'] = mv_value_list.pop()
                                        if right_a['type'] not in list_of_types:
                                            list_of_types.append(right_a['type'])
                                        v['Attribute'].append(
                                            getattribute(right_a,
                                                         pipesplit,
                                                         object_dict))
                                    else:
                                        if attribute['type'] not in list_of_types:
                                            list_of_types.append(attribute['type'])
                                        v['Attribute'].append(
                                            getattribute(attribute,
                                                         pipesplit,
                                                         object_dict))

                    output_table.append(v)

        if output_table:
            return get_attribute_columns()

    return list()


@Configuration(distributed=False)
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
    date = Option(
        doc='''
        **Syntax:** **date=***The user set event date field
         - any of valid time related filters"*
        **Description:**the user set date field on event level.
        The date format follows ISO 8061.
        **eventid**, **last** and **date** are mutually exclusive''',
        require=False, validate=validators.Match("date", r"^[0-9\-,d]+$"))
    eventid = Option(
        doc='''
        **Syntax:** **eventid=***id1(,id2,...)*
        **Description:**list of event ID(s) or event UUID(s).''',
        require=False, validate=validators.Match("eventid", r"^[0-9a-f,\-]+$"))
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False)
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:** deprecated alias of published_timestamp''',
        require=False, validate=validators.Match("last", r"^[0-9]+[hdm]$"))
    publish_timestamp = Option(
        doc='''
        **Syntax:** **publish_timestamp=***<int>d|h|m*
        **Description:** Restrict the results by the timestamp of the last
        publishing of the event. The input can be a timsetamp or a short-hand
        time description (7d or 24h for example). You can also pass a list with
        two values to set a time range (for example "14d,7d").''',
        require=False, validate=validators.Match(
            "publish_timestamp", r"^[0-9]+[dhm]?(,[0-9]+[dhm])?$"))
    timestamp = Option(
        doc='''
        **Syntax:** **publish_timestamp=***<int>d|h|m*
        **Description:** Restrict the results by the timestamp (last edit).
        Any event with a timestamp newer than the given timestamp will be
        returned. In case you are dealing with /attributes as scope, the
        attribute's timestamp will be used for the lookup. The input can be
        a timestamp or a short-hand time description (7d or 24h for example).
        You can also pass a list with two values to set a time range 
        (for example "14d,7d").''',
        require=False, validate=validators.Match(
            "timestamp", r"^[0-9]+[dhm]?(,[0-9]+[dhm])?$"))

    # Other params
    category = Option(
        doc='''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for.
         Wildcard is %.''',
        require=False)
    expand_object = Option(
        doc='''
        **Syntax:** **gexpand_object=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to have object attributes expanded one per line.
        By default, attributes of one object are displayed on same line.''',
        require=False, validate=validators.Boolean())
    getioc = Option(
        doc='''
        **Syntax:** **getioc=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return the list of attributes
         together with the event.''',
        require=False, validate=validators.Boolean())
    keep_galaxy = Option(
        doc='''
        **Syntax:** **keep_galaxy=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to remove galaxy part (useful with output=raw)''',
        require=False, validate=validators.Boolean())
    keep_related = Option(
        doc='''
        **Syntax:** **keep_galaxy=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to remove related events per attribute (useful with output=raw)''',
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
    only_to_ids = Option(
        doc='''
        **Syntax:** **only_to_ids=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to search only attributes with the flag
         "to_ids" set to true.''',
        require=False, validate=validators.Boolean())
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

    def log_error(self, msg):
        logging.error(msg)

    def log_info(self, msg):
        logging.info(msg)

    def log_debug(self, msg):
        logging.debug(msg)

    def log_warn(self, msg):
        logging.warning(msg)

    def set_log_level(self):
        # global configuration
        conf_file = "misp42splunk_settings"
        confs = self.service.confs[str(conf_file)]

        # set loglevel
        loglevel = 'INFO'
        for stanza in confs:
            if stanza.name == 'logging':
                for stanzakey, stanzavalue in stanza.content.items():
                    if stanzakey == "loglevel":
                        loglevel = stanzavalue
        logginglevel = logging.getLevelName(loglevel)
        log.setLevel(logginglevel)
        logging.error('[EV-101] logging level is set to %s', loglevel)
        logging.error('[EV-102] PYTHON VERSION: ' + sys.version)

    # @staticmethod
    def _record(
            serial_number, time_stamp, host, attributes,
            att_names, encoder, condensed=False):

        if condensed is False:
            raw = encoder.encode(attributes)
        # Formulate record
        fields = dict()
        for f in att_names:
            if f in attributes:
                fields[f] = attributes[f]

        if serial_number > 0:
            record = dict()
            record['_serial'] = serial_number
            record['_time'] = time_stamp
            if condensed is False:
                record['_raw'] = raw
            else:
                record['_raw'] = fields
            record['host'] = host
            record.update(fields)
            return record

        if condensed is False:
            record = OrderedDict(chain(
                (('_serial', serial_number), ('_time', time_stamp),
                 ('_raw', raw), ('host', host)),
                map(lambda name: (name, fields.get(name, '')), att_names)))
        else:
            record = OrderedDict(chain(
                (('_serial', serial_number), ('_time', time_stamp),
                 ('host', host), ('_raw', fields)),
                map(lambda name: (name, fields.get(name, '')), att_names)))

        return record

    def generate(self):
        # loggging
        self.set_log_level()
        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if my_args is None:
            raise Exception(
                "Sorry, no configuration for misp_instance={}".format(misp_instance))
        my_args['host'] = str(my_args['misp_url']).replace('https://', '')
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
        if self.publish_timestamp:
            mandatory_arg = mandatory_arg + 1
        if self.timestamp:
            mandatory_arg = mandatory_arg + 1

        if mandatory_arg == 0:
            self.log_error('Missing "timestamp", "json_request", eventid", \
                "publish_timestamp" or "date" argument')
            raise Exception('Missing "timestamp", "json_request", eventid", \
                "publish_timestamp" or "date" argument')
        elif mandatory_arg > 1:
            self.log_error('Options "timestamp", "json_request", eventid", \
                "last"(deprecated),  "publish_timestamp" \
                and "date" are mutually exclusive')
            raise Exception('Options "timestamp", "json_request", eventid", \
                "last"(deprecated),  "publish_timestamp" \
                and "date" are mutually exclusive')

        body_dict = dict()
        # Only ONE combination was provided
        if self.timestamp is not None:
            if "," in self.timestamp:  # contain a range
                timestamp_list = self.timestamp.split(",")
                body_dict['timestamp'] = [str(timestamp_list[0]),
                                          str(timestamp_list[1])]
                self.log_info(
                    'Option "timestamp" with range {}'
                    .format(json.dumps(body_dict['timestamp'])))
            else:  # contain a timestamp EPOCH or relative time
                body_dict['timestamp'] = self.timestamp
                self.log_info(
                    'Option "timestamp" {}'
                    .format(json.dumps(body_dict['timestamp'])))
        elif self.publish_timestamp is not None:
            if "," in self.publish_timestamp:  # contain a range
                publish_list = self.publish_timestamp.split(",")
                body_dict['publish_timestamp'] = [str(publish_list[0]),
                                                  str(publish_list[1])]
                self.log_info(
                    'Option "publish_timestamp " with range {}'
                    .format(json.dumps(body_dict['publish_timestamp'])))
            else:
                body_dict['publish_timestamp'] = self.publish_timestamp
                self.log_info(
                    'Option "publish_timestamp " {}'
                    .format(json.dumps(body_dict['publish_timestamp'])))
        elif self.json_request is not None:
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
        if self.expand_object is True:
            expand_object = True
        else:
            expand_object = False
        if self.getioc is True:
            getioc = True
        else:
            getioc = False
        if self.keep_galaxy is False:
            keep_galaxy = False
        else:
            keep_galaxy = True
        if self.keep_related is False:
            keep_related = False
        else:
            keep_related = True
        if self.only_to_ids is True:
            only_to_ids = True
        else:
            only_to_ids = False
        if self.output is not None:
            output = self.output
        else:
            output = "default"
        if self.pipesplit is True:
            pipesplit = True
        else:
            pipesplit = False

        if pagination is True:
            body_dict['page'] = page
            body_dict['limit'] = limit

        connection, connection_status = urllib_init_pool(self, my_args)
        if connection:
            response = urllib_request(
                self,
                connection,
                'POST',
                my_args['misp_url'],
                body_dict,
                my_args)
        else:
            response = connection_status

        if "_raw" in response:
            yield response
        else:
            encoder = json.JSONEncoder(
                ensure_ascii=False, separators=(',', ':'))
            if output == "raw":
                if 'response' in response:
                    attribute_names = list()
                    serial_number = 0
                    for r_item in response['response']:
                        if 'Event' in r_item:
                            for e in r_item.values():
                                if keep_galaxy is False:
                                    e.pop('Galaxy', None)
                                if keep_related is False:
                                    e.pop('RelatedEvent', None)
                                yield MispGetEventCommand._record(
                                    serial_number,
                                    e['timestamp'],
                                    my_args['host'],
                                    e, attribute_names,
                                    encoder)
                            serial_number += 1
                            GeneratingCommand.flush
            else:
                # build output table and list of types
                events = []
                typelist = []
                column_list = format_output_table(
                    response,
                    events,
                    typelist,
                    getioc,
                    pipesplit,
                    only_to_ids)
                self.log_info(
                    'typelist containss {} values'.format(len(typelist)))
                self.log_info(
                    'results contains {} records'.format(len(events)))

                if getioc is False:
                    attribute_names = list()
                    init_attribute_names = True
                    serial_number = 0
                    for e in events:
                        if init_attribute_names is True:
                            for key in e.keys():
                                if key not in attribute_names:
                                    attribute_names.append(key)
                            attribute_names.sort()
                            init_attribute_names = False
                        yield MispGetEventCommand._record(
                            serial_number, e['misp_timestamp'],
                            my_args['host'], e, attribute_names, encoder, True)
                        serial_number += 1
                        GeneratingCommand.flush
                else:
                    output_dict = dict()
                    for e in events:
                        if 'Attribute' in e:
                            for a in e['Attribute']:
                                if int(a['misp_object_id']) == 0:  # not an object
                                    key = str(e['misp_event_uuid']) + '_' \
                                        + str(a['misp_attribute_uuid'])
                                    is_object_member = False
                                else:  # this is a MISP object
                                    if expand_object is True:
                                        # compute key based on attribute UUID
                                        key = str(e['misp_event_uuid']) + '_' \
                                            + str(a['misp_attribute_uuid'])
                                    else:
                                        key = str(e['misp_event_id']) + \
                                            '_object_' + str(a['misp_object_id'])
                                    is_object_member = True

                                if key not in output_dict:
                                    v = init_misp_output(e, a, column_list)
                                    for t in typelist:
                                        misp_t = 'misp_' \
                                            + t.replace('-', '_')\
                                                 .replace('|', '_p_')
                                        if t == a['misp_type']:
                                            v[misp_t] = str(a['misp_value'])
                                    output_dict[key] = dict(v)
                                else:
                                    v = dict(output_dict[key])
                                    misp_t = 'misp_' + str(a['misp_type'])\
                                        .replace('-', '_').replace('|', '_p_')
                                    if misp_t in v:
                                        if isinstance(v[misp_t], str):
                                            temp_attribute = v[misp_t]
                                            v[misp_t] = list()
                                            v[misp_t].append(temp_attribute)
                                        v[misp_t].append(str(a['misp_value']))
                                    else:
                                        v[misp_t] = str(a['misp_value'])

                                    if is_object_member is True:
                                        for ac in column_list:
                                            if ac in a and ac in v:
                                                if a[ac]:
                                                    if ac.startswith("misp_object_"):
                                                        if not v[ac]:
                                                            v[ac] = a[ac]
                                                        elif isinstance(v[ac], str):
                                                            if a[ac] != v[ac]:
                                                                temp_attribute = v[ac]
                                                                v[ac] = list()
                                                                v[ac].append(temp_attribute)
                                                                v[ac].append(a[ac])
                                                        elif a[ac] not in v[ac]:
                                                            v[ac].append(a[ac])
                                                    else:
                                                        if not v[ac]:
                                                            v[ac] = a[ac]
                                                        elif isinstance(v[ac], str):
                                                            temp_attribute = v[ac]
                                                            v[ac] = list()
                                                            v[ac].append(temp_attribute)
                                                            v[ac].append(a[ac])
                                                        else:
                                                            v[ac].append(a[ac])
                                    else:  # replace mv by original value
                                        v['misp_type'] = a['misp_type'] \
                                            + '|' + v['misp_type']
                                        v['misp_value'] = a['misp_value'] + \
                                            '|' + v['misp_value']

                                    # if a['misp_attribute_tag']:
                                    #     a_tag = v['misp_attribute_tag'] \
                                    #         + a['misp_attribute_tag']
                                    #     # unique_tag = list(set(a_tag))
                                    #     v['misp_attribute_tag'] = a_tag

                                    output_dict[key] = dict(v)

                    if output_dict is not None:
                        attribute_names = list()
                        init_attribute_names = True
                        serial_number = 0
                        for v in output_dict.values():
                            if init_attribute_names is True:
                                attribute_names = list(v.keys())
                                for t in typelist:
                                    misp_t = 'misp_' \
                                        + t.replace('-', '_')\
                                             .replace('|', '_p_')
                                    if misp_t not in attribute_names:
                                        attribute_names.append(misp_t)
                                attribute_names.sort()
                                init_attribute_names = False
                            yield MispGetEventCommand._record(
                                serial_number, v['misp_timestamp'],
                                my_args['host'], v,
                                attribute_names, encoder, True)
                            serial_number += 1
                            GeneratingCommand.flush


if __name__ == "__main__":
    dispatch(MispGetEventCommand, sys.argv, sys.stdin, sys.stdout, __name__)
