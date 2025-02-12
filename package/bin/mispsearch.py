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

from itertools import chain
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from misp_common import prepare_config, logging_level, urllib_init_pool, get_attributes, map_attribute_table
import json
import logging
import sys

"""
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
"""

MISPSEARCH_INIT_PARAMS = {
    # optional parameters for request
    'misp_http_body': None,
    'limit': 10,
    'page': 1,
    'not_tags': None,
    'tags': None,
    # optional parameters to format results
    'pipesplit': True,
    'prefix': 'misp_'
}

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "5.0.0"
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
        **Description:**MISP instance parameters as described in local/misp42splunk_instances.conf
        ''',
        require=True)
    field = Option(
        doc='''
        **Syntax:** **field=***<fieldname>*
        **Description:**Name of the field containing the value to search for.
        ''',
        require=True,
        validate=validators.Fieldname())
    misp_http_body = Option(
        doc='''
        **Syntax:** misp_http_body=<JSON>
        **Description:**Valid JSON request
        ''',
        require=False
    )
    limit = Option(
        doc='''
        **Syntax:** limit=<int>
        **Description:**define the limit for each request to MISP. 0 = no pagination.
        **Default:** 1000
        ''',
        require=False,
        default=10,
        validate=validators.Integer()
    )
    not_tags = Option(
        doc='''
        **Syntax:** not_tags=<string>,<string>*
        **Description:**Comma(,)-separated string of tags to exclude. Wildcard is %.
        ''',
        require=False
    )
    page = Option(
        doc='''
        **Syntax:** **page=** *<int>*
        **Description:** define the page when limit is not 0.
        **Default:** 0 - get all pages
        ''',
        require=False, 
        default=1,
        validate=validators.Integer()
    )
    pipesplit = Option(
        doc='''
        **Syntax:** pipesplit=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to split multivalue attributes.
        **Default:** False
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )
    prefix = Option(
        doc='''
        **Syntax:** **prefix=** *<string>*
        **Description:** string to use as prefix for misp keys
        **Default:** misp_
        ''',
        require=False, 
        default="misp_", 
        validate=validators.Match("prefix", r"^[a-zA-Z][a-zA-Z0-9_]+$")
    )
    tags = Option(
        doc='''
        **Syntax:** tags=<string>,<string>
        **Description:**Comma(,)-separated string of tags to search for. Wildcard is %.
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
        logging.root
        loglevel = logging_level('misp42splunk')
        logging.root.setLevel(loglevel)
        logging.error('[SE-101] logging level is set to %s', loglevel)
        logging.error('[SE-102] PYTHON VERSION: ' + sys.version)

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

    def create_se_params(self, last_record):
        field_values = dict(
            chain(
                map(
                    lambda name: (
                        name,
                        self.get_parameter(
                            last_record,
                            name,
                            default=MISPSEARCH_INIT_PARAMS[name])),
                    list(MISPSEARCH_INIT_PARAMS.keys())
                )))

        for field in list(MISPSEARCH_INIT_PARAMS.keys()):
            if isinstance(MISPSEARCH_INIT_PARAMS[field], bool):
                if field in field_values:
                    field_values[field] = self.check_true_bool(
                        field_values[field])

        return field_values

    def stream(self, records):
        # loggging
        self.set_log_level()

        config = dict()
        # Phase 1: Preparation
        # extract parameters from last record from input set
        # Phase 1: Preparation
        try:
            dummy_record = {"misp_app": "misp42"}
            se_params = self.create_se_params(dummy_record)
            self.log_info('[SE-201] ms_params {}'.format(se_params))
        except Exception as e:
            raise Exception("[SE-202] Sorry, ms_params failed {}".format(e))
        
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        config = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if config is None:
            raise Exception("[SE-203] Sorry, no configuration for misp_instance={}".format(misp_instance))
        config.update(se_params)
        config['misp_url'] = config['misp_url'] + '/attributes/restSearch'

        connection, connection_status = urllib_init_pool(self, config)

        config['fieldname'] = str(self.field)
        if self.prefix:
            config['prefix'] = self.prefix
        prefix = config['prefix']
        for record in records:
            if config['fieldname'] in record:
                try:
                    se_params = self.create_se_params(record)
                except Exception:
                    pass
                config.update(se_params)

                if config['misp_http_body'] is None:
                    # Force some values on JSON request
                    body_dict = dict()
                else:
                    body_dict = dict(json.loads(config['misp_http_body']))
                # enforce returnFormat to JSON
                body_dict['returnFormat'] = 'json'
                body_dict['withAttachments'] = False
                body_dict['includeEventTags'] = True
                body_dict['includeEventUuid'] = True
                body_dict['includeSightings'] = body_dict.get('includeSightings', True)

                if 'tags' not in body_dict:
                    if config['tags'] is not None or\
                       config['not_tags'] is not None:
                        tags_criteria = {}
                        if config['tags'] is not None:
                            tags_criteria['OR'] = config['tags'].split(",")
                        if config['not_tags'] is not None:
                            tags_criteria['NOT'] = config['not_tags'].split(",")
                        if tags_criteria is not None:
                            body_dict['tags'] = tags_criteria

                config['limit'] = body_dict.get('limit', config['limit'])
                config['page'] = body_dict.get('page', config['page'])
                config['include_sightings'] = body_dict.get('includeSightings', True)  # default true whithout additional param
 
                self.log_info('[SE-204] actual http body: {} '.format(json.dumps(body_dict)))

                value = record.get(config['fieldname'], None)
                if value not in [None, '', 0, "0", "%"]:
                    body_dict['value'] = str(value)
                    # search
                    if connection:
                        response_list = get_attributes(self, connection, config, body_dict)
                        attribute_list = map_attribute_table(self, response_list, config)
                        merged_list = dict()
                        for attribute in attribute_list:
                            for a_key, a_value in attribute.items():
                                if a_key not in merged_list:
                                    merged_list[a_key] = []
                                if a_value not in [None, '']:
                                    if isinstance(a_value, list):
                                        for a_value_item in a_value:
                                            if a_value_item not in merged_list[a_key]:
                                                merged_list[a_key].append(a_value_item)
                                    else:
                                        if a_value not in merged_list[a_key]:
                                            merged_list[a_key].append(a_value)

                            attribute_key = prefix + 'attributes'
                            if attribute_key not in merged_list:
                                merged_list[attribute_key] = []
                            merged_list[attribute_key].append(attribute)
                        record.update(merged_list)
            # return enriched record
            yield record


if __name__ == "__main__":
    dispatch(MispSearchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
