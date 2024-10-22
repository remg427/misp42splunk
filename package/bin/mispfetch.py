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
from misp_common import prepare_config, urllib_init_pool, urllib_request
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import os
from splunklib.six.moves import map
import sys
import uuid

splunkhome = os.environ['SPLUNK_HOME']

# set logging
filehandler = logging.FileHandler(splunkhome
                                  + "/var/log/splunk/misp42splunk.log", 'a')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(filename)s \
                              %(funcName)s %(lineno)d %(message)s')
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)      # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.4.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


MISPFETCH_INIT_PARAMS = {
    # mandatory parameter for mispfetch
    'misp_instance': None,
    # optional parameters
    'misp_restsearch': 'events',
    'misp_http_body': None,
    'misp_output_mode': 'fields',
    'expand_object': False,
    'getioc': False,
    'keep_galaxy': True,
    'only_to_ids': False,
    'pipesplit': False,
    'limit': 1000,
    'attribute_limit': 1000,
    'not_tags': None,
    'tags': None}


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
            if tag['name'] not in tag_list:
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


def format_event_output_table(input_json, output_table, list_of_types,
                              host, get_attr=False, pipesplit=False,
                              only_to_ids=False):

    # process events and return a list of events
    # if get_attr is True each event entry contains a key Attribute
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
                    v['misp_host'] = host
                    v['misp_tag'] = tag_list
                    if get_attr is True:
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
                                        if (
                                            only_to_ids is False or
                                                (
                                                    only_to_ids is True and
                                                    attribute['to_ids'] is True
                                                )
                                        ):
                                            if attribute['type'] \
                                               not in list_of_types:
                                                list_of_types.append(
                                                    attribute['type'])
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
                                            list_of_types.append(
                                                left_a['type'])
                                        v['Attribute'].append(
                                            getattribute(left_a,
                                                         pipesplit,
                                                         object_dict))
                                        right_a = attribute.copy()
                                        right_a['type'] = mv_type_list.pop()
                                        right_a['value'] = mv_value_list.pop()
                                        if right_a['type'] \
                                           not in list_of_types:
                                            list_of_types.append(
                                                right_a['type'])
                                        v['Attribute'].append(
                                            getattribute(right_a,
                                                         pipesplit,
                                                         object_dict))
                                    else:
                                        if attribute['type'] not in list_of_types:
                                            list_of_types.append(
                                                attribute['type'])
                                        v['Attribute'].append(
                                            getattribute(attribute,
                                                         pipesplit,
                                                         object_dict))

                    output_table.append(v)

        if output_table:
            return get_attribute_columns()

    return list()


def format_attribute_output_table(input_json, output_table,
                                  list_of_types, host,
                                  pipesplit=False, only_to_ids=False):

    common_columns = ["category", "to_ids", "timestamp", "comment",
                      "deleted", "disable_correlation",
                      "first_seen", "last_seen", "object_id",
                      "object_relation", "type", "value"]
    attribute_specific_columns = ["id", "distribution",
                                  "sharing_group_id", "uuid"]
    attr_event_columns = ["id", "uuid", "distribution", "info"]
    organisation_columns = ["org_id", "orgc_id"]

    if 'response' in input_json:
        if 'Attribute' in input_json['response']:
            for a in input_json['response']['Attribute']:
                if (
                    only_to_ids is False or
                    (
                        only_to_ids is True and
                        a['to_ids'] is True
                    )
                ):
                    v = dict()
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
                    tag_list = list()
                    if 'Tag' in a:
                        for tag in a['Tag']:
                            try:
                                tag_list.append(str(tag['name']))
                            except Exception:
                                pass
                    v['misp_host'] = host
                    v['misp_tag'] = tag_list
                    # include Event metatdata
                    if 'Event' in a:
                        for aec in attr_event_columns:
                            misp_aec = "misp_event_" + aec
                            if aec in a['Event']:
                                v[misp_aec] = str(a['Event'][aec])
                        for oc in organisation_columns:
                            misp_oc = "misp_" + oc
                            if oc in a['Event']:
                                v[misp_oc] = str(a['Event'][oc])

                    current_type = str(a['type'])
                    # combined: not part of an object
                    # AND multivalue attribute AND to be split
                    if int(a['object_id']) == 0 and '|' in current_type\
                       and pipesplit is True:
                        mv_type_list = current_type.split('|')
                        mv_value_list = str(a['value']).split('|')
                        left_v = v.copy()
                        left_v['misp_type'] = str(mv_type_list.pop())
                        left_v['misp_value'] = str(mv_value_list.pop())
                        output_table.append(left_v)
                        if left_v['misp_type'] not in list_of_types:
                            list_of_types.append(left_v['misp_type'])
                        right_v = v.copy()
                        right_v['misp_type'] = str(mv_type_list.pop())
                        right_v['misp_value'] = str(mv_value_list.pop())
                        output_table.append(right_v)
                        if right_v['misp_type'] not in list_of_types:
                            list_of_types.append(right_v['misp_type'])
                    else:
                        output_table.append(v)
                        if current_type not in list_of_types:
                            list_of_types.append(current_type)


def format_attribute_output_json(input_json, output_dict, host):
    common_columns = ["category", "to_ids", "timestamp",
                      "first_seen", "last_seen", "type", "value"]
    attribute_specific_columns = ["id", "uuid"]
    attr_event_columns = ["id", "uuid", "distribution", "info"]
    organisation_columns = ["org_id", "orgc_id"]

    if 'response' in input_json:
        if 'Attribute' in input_json['response']:
            for a in input_json['response']['Attribute']:
                v = dict()
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
                tag_list = list()
                if 'Tag' in a:
                    for tag in a['Tag']:
                        try:
                            tag_list.append(str(tag['name']))
                        except Exception:
                            pass
                v['misp_host'] = host
                v['misp_tag'] = tag_list
                # include Event metatdata
                if 'Event' in a:
                    for aec in attr_event_columns:
                        misp_aec = "misp_event_" + aec
                        if aec in a['Event']:
                            v[misp_aec] = str(a['Event'][aec])
                    for oc in organisation_columns:
                        misp_oc = "misp_" + oc
                        if oc in a['Event']:
                            v[misp_oc] = str(a['Event'][oc])
                v['misp_json'] = a
                key = a['uuid']
                output_dict[key] = v


@Configuration(distributed=False)
class MispFetchCommand(StreamingCommand):

    """ get the attributes from a MISP instance.
    ##Syntax
    .. code-block::
        | MispFetchCommand misp_instance=<input> last=<int>(d|h|m)
        | MispFetchCommand misp_instance=<input> event=<id1>(,<id2>,...)
        | MispFetchCommand misp_instance=<input> date=<<YYYY-MM-DD>
                                            (date_to=<YYYY-MM-DD>)
    ##Description
    ### /attributes/restSearch
    #### from REST client
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
        "event_tags": "optional",
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
        "sharinggroup": "optional",
        "excludeLocalTags": "optional",
        "threat_level_id": "optional"
    }
    #### Parameters directly available
    {
        "returnFormat": "json",
        "limit": managed,
        "tag": managed
        "not_tags": managed
        "withAttachments": False
    }

    ### /events/restSearch
    #### from REST client
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
        "event_tags": "optional",
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
        "sharinggroup": "optional",
        "excludeLocalTags": "optional",
        "threat_level_id": "optional"
    }

    #### Parzameters directly available
    {
        "returnFormat": "json",
        "limit": managed,
        "tags": managed
        "not_tags": managed
        "withAttachments": False
    }
    """
    # MANDATORY MISP instance for this search
    misp_instance = Option(
        doc='''
        **Syntax:** misp_instance=<string>
        **Description:**MISP instance parameters as described
         in local/misp42splunk_instances.conf.
         ''',
        require=False
    )

    misp_restsearch = Option(
        doc='''
        **Syntax:** misp_restsearch=<string>
        **Description:**define the restSearch endpoint.
        Either "events" or "attributes". Default events
        ''',
        require=False, 
        validate=validators.Match(
            "misp_restsearch", r"^(events|attributes)$")
    )

    misp_http_body = Option(
        doc='''
        **Syntax:** misp_http_body=<JSON>
        **Description:**Valid JSON request
        ''',
        require=False
    )

    misp_output_mode = Option(
        doc='''
        **Syntax:** misp_output_mode=<string>
        **Description:**define how to render on Splunk either as native
        tabular view (`fields`)or JSON object (`json`).
        ''',
        require=False,
        default="fields",
        validate=validators.Match(
            "misp_output_mode", r"^(fields|json)$")
    )

    expand_object = Option(
        doc='''
        **Syntax:** expand_object=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to expand object attributes one per line.
        By default, attributes of one object are displayed on same line.
        ''',
        require=False, 
        validate=validators.Boolean()
    )

    getioc = Option(
        doc='''
        **Syntax:** getioc=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to return the list of attributes
         together with the event.
        ''',
        require=False, 
        validate=validators.Boolean()
    )

    keep_galaxy = Option(
        doc='''
        **Syntax:** keep_galaxy=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to remove galaxy part
        (useful with misp_output_mode=json)
        ''',
        require=False, 
        validate=validators.Boolean()
    )

    limit = Option(
        doc='''
        **Syntax:** limit=<int>
        **Description:**define the limit for each MISP search 
        0 = no pagination.
        ''',
        require=False,
        default=1000,
        validate=validators.Integer()
    )

    attribute_limit = Option(
        doc='''
        **Syntax:** attribute_limit=<int>
        **Description:**define the attribute_limit for max count of
         returned attributes for each MISP default;
         default 1000. 0 = no pagination.
        ''',
        require=False, 
        default=1000,
        validate=validators.Integer()
    )

    not_tags = Option(
        doc='''
        **Syntax:** not_tags=<string>,<string>*
        **Description:**Comma(,)-separated string of tags to exclude.
        Wildcard is %.
        ''',
        require=False
    )

    only_to_ids = Option(
        doc='''
        **Syntax:** only_to_ids=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to search only attributes with the flag
         "to_ids" set to true.
         ''',
        require=False,
        validate=validators.Boolean()
    )

    pipesplit = Option(
        doc='''
        **Syntax:** pipesplit=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to split multivalue attributes.
        ''',
        require=False,
        validate=validators.Boolean()
    )

    tags = Option(
        doc='''
        **Syntax:** tags=<string>,<string>
        **Description:**Comma(,)-separated string of tags to search for.
         Wildcard is %.
        ''',
        require=False
    )

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

    # get parameters from record or command line
    def get_parameter(self, obj, key, default=False):
        if key in obj:
            return obj[key]
        else:
            key_param = getattr(self, key)
            if key_param is not None:
                return key_param
            else:
                return default

    def check_true_bool(self, field):
        if field is True or str(field).lower() in ["1", "y", "t", "true"]:
            return True
        else:
            return False

    def create_mf_params(self, last_record):
        field_values = dict(
            chain(
                map(
                    lambda name: (
                        name,
                        self.get_parameter(
                            last_record,
                            name,
                            default=MISPFETCH_INIT_PARAMS[name])),
                    list(MISPFETCH_INIT_PARAMS.keys())
                )))

        for field in list(MISPFETCH_INIT_PARAMS.keys()):
            if isinstance(MISPFETCH_INIT_PARAMS[field], bool):
                if field in field_values:
                    field_values[field] = self.check_true_bool(
                        field_values[field])

        return field_values

    def report_events(self, output_dict, events, result_columns,
                      attr_columns, typelist,
                      get_attr=False, attr_limit=1000,
                      expand_obj=False):

        if get_attr is False:
            self.log_info(
                '[MF-310] as getioc={}, returning only event \
                metadata'.format(get_attr))
            init_result_columns = True
            for e in events:
                if 'Attribute' in e:
                    e.pop('Attribute')
                if init_result_columns is True:
                    for key in e.keys():
                        if key not in result_columns:
                            result_columns.append(key)
                    result_columns.sort()
                    init_result_columns = False
                key = e['misp_event_uuid']
                e['_time'] = e['misp_timestamp']
                output_dict[key] = e
        else:
            self.log_info(
                '[MF-320] as getioc={}, returning event \
                and their attributes (limited to {} attributes \
                per event)'.format(get_attr, attr_limit))
            for e in events:
                if 'Attribute' in e:
                    attribute_count = int(attr_limit)
                    self.log_info(
                        '[MF-321] attribute_limit={}'.format(attribute_count))
                    for a in e['Attribute']:
                        if attribute_count > 0:
                            if int(a['misp_object_id']) == 0:  # not an object
                                key = str(e['misp_event_uuid']) + '_' \
                                    + str(a['misp_attribute_uuid'])
                                is_object_member = False
                            else:  # this is a MISP object
                                if expand_obj is True:
                                    # compute key based on attribute UUID
                                    key = str(e['misp_event_uuid']) + '_' \
                                        + str(a['misp_attribute_uuid'])
                                else:
                                    key = str(e['misp_event_id']) + \
                                        '_object_' + str(a['misp_object_id'])
                                is_object_member = True

                            if key not in output_dict:
                                self.log_info(
                                    '[MF-322] adding new key {}'.format(key))
                                v = init_misp_output(e, a, attr_columns)
                                for t in typelist:
                                    misp_t = 'misp_' \
                                        + t.replace('-', '_')\
                                             .replace('|', '_p_')
                                    if t == a['misp_type']:
                                        v[misp_t] = str(a['misp_value'])
                                v['_time'] = v['misp_timestamp']
                                output_dict[key] = dict(v)
                                attribute_count -= 1
                                self.log_debug(
                                    '[MF-328] adding 1 event to output_dict.\
                                    Now it has {} item(s)'
                                    .format(len(output_dict)))
                            else:
                                self.log_info(
                                    '[MF-323] updating key {}'.format(key))
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
                                    for ac in attr_columns:
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
                                attribute_count -= 1
                                self.log_debug(
                                    '[MF-329] adding 1 event to output_dict.\
                                    Now it has {} item(s)'
                                    .format(len(output_dict)))

    def report_attributes(self, output_dict, attributes, typelist,
                          expand_object=False):
        common_columns = ["category", "to_ids", "timestamp", "comment",
                          "deleted", "disable_correlation",
                          "first_seen", "last_seen", "object_id",
                          "object_relation", "type", "value"]
        attribute_specific_columns = ["id", "distribution",
                                      "sharing_group_id", "uuid"]

        # consolidate attribute values under output table
        for r in attributes:
            if int(r['misp_object_id']) == 0:  # not an object
                key = str(r['misp_event_id']) + \
                    '_' + str(r['misp_attribute_id'])
                is_object_member = False
            else:  # this is a  MISP object
                if expand_object is False:
                    # join attributes in 1 row
                    # key is based on object id
                    key = str(r['misp_event_id']) \
                        + '_object_' + str(r['misp_object_id'])
                else:
                    # setting key on attribute uuid to keep
                    # several rows for one object
                    key = str(r['misp_event_id']) + \
                        '_' + str(r['misp_attribute_id'])
                is_object_member = True

            if key not in output_dict:
                # first item - store on dictionary
                v = dict(r)
                for t in typelist:
                    misp_t = 'misp_'\
                        + t.replace('-', '_').replace('|', '_p_')
                    v[misp_t] = list()
                    if t == r['misp_type']:
                        v[misp_t].append(r['misp_value'])
            else:
                v = dict(output_dict[key])
                if is_object_member is False:
                    # this is a combo field and pipesplit was set to True
                    # restore original type and value
                    # (individual misp fields remain)
                    misp_t = 'misp_'\
                        + r['misp_type'].replace('-', '_').replace('|', '_p_')
                    v[misp_t].append(r['misp_value'])  # set value for type
                    misp_type = r['misp_type'] + '|' + v['misp_type']
                    v['misp_type'] = list()
                    v['misp_type'].append(misp_type)
                    misp_value = str(r['misp_value']) + '|'\
                        + str(v['misp_value'])
                    v['misp_value'] = list()
                    v['misp_value'].append(misp_value)
                else:
                    # this is an object with several attributes
                    # they are returned one by one but here
                    # should be grouped on one record.
                    # The field in an object can have several values.
                    misp_t = 'misp_' + r['misp_type'].replace(
                        '-', '_').replace('|', '_p_')
                    v[misp_t].append(r['misp_value'])  # set value for type
                    for ac in common_columns:
                        misp_ac = "misp_" + ac
                        if misp_ac in r:
                            if misp_ac not in v:
                                v[misp_ac] = list()
                            elif isinstance(v[misp_ac], str):
                                temp = v[misp_ac]
                                v[misp_ac] = list()
                                v[misp_ac].append(temp)
                            v[misp_ac].append(str(r[misp_ac]))
                    for asc in attribute_specific_columns:
                        misp_asc = "misp_attribute_" + asc
                        if misp_asc in r:
                            if misp_asc not in v:
                                v[misp_asc] = list()
                            elif isinstance(v[misp_asc], str):
                                temp = v[misp_asc]
                                v[misp_asc] = list()
                                v[misp_asc].append(temp)
                            v[misp_asc].append(str(r[misp_asc]))
                    tag_list = v['misp_tag']
                    for tag in r['misp_tag']:
                        if tag not in tag_list:
                            tag_list.append(tag)
                    v['misp_tag'] = tag_list
            output_dict[key] = dict(v)

    # @staticmethod
    def _record(
            serial_number, attributes,
            att_names):

        # Formulate record
        fields = dict()
        for f in att_names:
            if f in attributes:
                fields[f] = attributes[f]

        if serial_number > 0:
            row = dict()
            row.update(fields)
        else:
            row = OrderedDict(chain(
                map(lambda name: (name, fields.get(name, '')), att_names)))

        return row

    def stream(self, records):

        self.set_log_level()

        output_dict = dict()
        my_args = dict()
        result_columns = list()
        for record in records:
            key = uuid.uuid4().hex
            output_dict[key] = record

            # extract parameters from last record from input set
            # Phase 1: Preparation
            try:
                mf_params = self.create_mf_params(record)
                self.mf_params = mf_params
                self.log_info('[MF-050] mf_params {}'.format(mf_params))

            except Exception as e:
                raise Exception(
                    "[MF-001] Sorry, mf_params failed {}".format(e))

            if mf_params['misp_instance'] is None:
                raise Exception(
                    "Sorry, self.mf_params['misp_instance'] is not defined")
            storage = self.service.storage_passwords
            my_args = prepare_config(self,
                                     'misp42splunk',
                                     mf_params['misp_instance'],
                                     storage)
            if my_args is None:
                raise Exception(
                    "Sorry, no configuration for misp_instance={}"
                    .format(mf_params['misp_instance']))
            my_args['host'] = str(my_args['misp_url']).replace('https://', '')
            if mf_params['misp_restsearch'] == "events":
                my_args['misp_url'] = my_args['misp_url'] + '/events/restSearch'
            elif mf_params['misp_restsearch'] == "attributes":
                my_args['misp_url'] = my_args['misp_url']\
                    + '/attributes/restSearch'
            self.log_info(
                '[MF-030] misp_instance {} restSearch {} url {}'
                .format(mf_params['misp_instance'],
                        mf_params['misp_restsearch'],
                        my_args['misp_url']))
            if mf_params['misp_http_body'] is None:
                # Force some values on JSON request
                body_dict = dict()
                body_dict['last'] = "1h"
                body_dict['published'] = True
            else:
                body_dict = dict(json.loads(
                    mf_params['misp_http_body']))
            # enforce returnFormat to JSON
            body_dict['returnFormat'] = 'json'
            body_dict['withAttachments'] = False

            if mf_params['tags'] is not None or\
               mf_params['not_tags'] is not None:
                tags_criteria = {}
                if mf_params['tags'] is not None:
                    tags_criteria['OR'] = mf_params['tags'].split(",")
                if mf_params['not_tags'] is not None:
                    tags_criteria['NOT'] = mf_params['not_tags'].split(",")
                body_dict['tags'] = tags_criteria

            if 'limit' not in body_dict:
                body_dict['limit'] = mf_params['limit']
            if 'page' in body_dict:
                mf_params['page'] = body_dict['page']
            else:
                mf_params['page'] = 0

            self.log_info(
                '[MF-100] actual http body: {} '.format(json.dumps(body_dict)))

            connection, connection_status = urllib_init_pool(self, my_args)
            if connection:
                if mf_params['page'] == 0:
                    request_loop = True
                    body_dict['page'] = 1
                    if mf_params['misp_restsearch'] == "events":
                        response = {'response': []}
                        while request_loop:
                            iter_response = urllib_request(
                                self,
                                connection,
                                'POST',
                                my_args['misp_url'],
                                body_dict,
                                my_args)
                            if 'response' in iter_response:
                                rlength = len(iter_response['response'])
                                self.log_debug(
                                    '[MF-401] returned event(s): {}'
                                    .format(rlength))
                                if rlength != 0:
                                    response['response'].extend(
                                        iter_response['response'])
                                    body_dict['page'] = body_dict['page'] + 1
                                else:
                                    # last page is reached
                                    request_loop = False
                            else:
                                request_loop = False
                    else:  # Attributes
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
                                    self.log_debug(
                                        '[MF-411] returned attribute(s): {}'
                                        .format(rlength))
                                    if rlength != 0:
                                        response['response']['Attribute'].extend(
                                            iter_response['response']['Attribute'])
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
                '[MF-200] response contains {} records'.format(len(response)))

            if mf_params['misp_restsearch'] == "events":
                if mf_params['misp_output_mode'] == "json":
                    self.log_info(
                        '[MF-301] misp_output_mode={}, returning event in JSON'
                        .format(mf_params['misp_output_mode']))
                    if 'response' in response:
                        event_specific_columns = ["id", "date", "info", "published", "uuid"]
                        organisation_columns = ["id", "name", "uuid", "local"]
                        for r_item in response['response']:
                            if 'Event' in r_item:
                                single_event = dict()
                                single_event['misp_json'] = r_item['Event']
                                single_event['misp_event_uuid'] = r_item['Event']['uuid']
                                single_event['misp_timestamp'] = r_item['Event']['timestamp']
                                single_event['misp_host'] = my_args['host']
                                single_event['_time'] = single_event['misp_timestamp']
                                # for a in list(r_item.values()):

                                # prepend key names with misp_event_
                                for esc in event_specific_columns:
                                    misp_esc = "misp_event_" + esc
                                    single_event[misp_esc] = str(r_item['Event'][esc])
                                if 'Org' in r_item['Event']:
                                    # prepend key names with misp_org_
                                    for oc in organisation_columns:
                                        misp_oc = "misp_org_" + oc
                                        single_event[misp_oc] = str(r_item['Event']['Org'][oc])
                                if 'Orgc' in r_item['Event']:
                                    # prepend key names with misp_orgc_
                                    for oc in organisation_columns:
                                        misp_oc = "misp_orgc_" + oc
                                        single_event[misp_oc] = str(r_item['Event']['Orgc'][oc])
                                # append attribute self.mf_params['tags'] to tag list
                                tag_list = list()
                                if 'Tag' in r_item['Event']:
                                    for tag in r_item['Event']['Tag']:
                                        try:
                                            tag_list.append(str(tag['name']))
                                        except Exception:
                                            pass
                                single_event['misp_tag'] = tag_list
                                key = single_event['misp_event_uuid']
                                self.log_info(
                                    '[MF-303] JSON event {}'.format(single_event))
                                output_dict[key] = single_event
                else:
                    # build output table and list of types
                    events = list()
                    typelist = list()
                    column_list = format_event_output_table(
                        response,
                        events,
                        typelist,
                        my_args['host'],
                        get_attr=mf_params['getioc'],
                        pipesplit=mf_params['pipesplit'],
                        only_to_ids=mf_params['only_to_ids'])
                    self.log_info(
                        '[MF-201] typelist contains {} values'
                        .format(len(typelist)))
                    self.log_info(
                        '[MF-202] results contains {} records'
                        .format(len(events)))

                    for output in output_dict.values():
                        for key in list(output.keys()):
                            if key not in result_columns:
                                result_columns.append(key)
                        for t in typelist:
                            misp_t = 'misp_' \
                                + t.replace('-', '_')\
                                     .replace('|', '_p_')
                            if misp_t not in result_columns:
                                result_columns.append(misp_t)
                    result_columns.sort()

                    self.report_events(output_dict, events, result_columns,
                                       column_list, typelist,
                                       get_attr=mf_params['getioc'],
                                       attr_limit=mf_params['attribute_limit'],
                                       expand_obj=mf_params['expand_object'])
            else:
                # add colums for each type in results
                attributes = list()
                typelist = list()
                if mf_params['misp_output_mode'] == "json":
                    format_attribute_output_json(response, output_dict, my_args['host'])
                else:
                    format_attribute_output_table(
                        response, attributes, typelist, my_args['host'],
                        pipesplit=mf_params['pipesplit'],
                        only_to_ids=mf_params['only_to_ids'])

                    self.report_attributes(output_dict,
                                           attributes,
                                           typelist,
                                           expand_object=mf_params['expand_object'])

            for output in output_dict.values():
                output.update(mf_params)
                for key in list(output.keys()):
                    if key not in result_columns:
                        result_columns.append(key)
            result_columns.sort()

            if output_dict is not None:
                # init columns of output
                serial_number = 0
                for v in output_dict.values():
                    yield MispFetchCommand._record(
                        serial_number, v, result_columns)
                    serial_number += 1


if __name__ == "__main__":
    dispatch(MispFetchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
