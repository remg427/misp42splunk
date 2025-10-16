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
import json
import misp42splunk_declare
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import sys
import logging
from misp_common import prepare_config, urllib_request, logging_level, urllib_init_pool

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "5.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(distributed=False)
class MispGetAttributeCommand(StreamingCommand):
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=** *instance_name*
        **Description:** MISP instance parameters as described in local/misp42splunk_instances.conf.
        ''',
        require=True
    )
    attributeid = Option(
        doc='''
        **Syntax:** **attributeid=** *id*
        **Description:** ID of attribute to check
        ''',
        require=False
    )
    fields = Option(
        doc='''
        **Syntax:** **fields=** *CSV string*
        **Description:** comma(,)-separated string of fields to use. Default is all fields.
        ''',
        require=False
    )
    prefix = Option(
        doc='''
        **Syntax:** **prefix=** *<string>*
        **Description:** string to use as prefix for misp keys
        ''',
        require=False, 
        validate=validators.Match("prefix", r"^[a-zA-Z][a-zA-Z0-9_]+$")
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
        logging.error('[EV-101] logging level is set to %s', loglevel)
        logging.error('[EV-102] PYTHON VERSION: ' + sys.version)

    def stream(self, records):
        self.set_log_level()
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        config = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if config is None:
            raise Exception(
                "[EV-101] Sorry, no configuration for misp_instance={}".format(misp_instance))
        base_url = config['misp_url'] + "/attributes/view/"
        
        shown_fields = []
        if self.fields:
            shown_fields = self.fields.replace(" ", "").split(",")
        filter_fields = len(shown_fields) > 0

        for record in records:
            if self.attributeid:
                attribute_id = self.attributeid
            elif "attributeid" in record:
                attribute_id = record["attributeid"]
            else:
                raise Exception("[AT-101] No attributeid found!")
            
            config['misp_url'] = base_url + str(attribute_id)

            connection, connection_status = urllib_init_pool(self, config)
            if connection is None:
                response = connection_status
                self.log_info('[AT-102] connection for {} failed'.format(config['misp_url']))
                yield record
                continue
            
            response = urllib_request(self, connection, "GET", config['misp_url'], {}, config)
            if "Attribute" in response:
                attribute_fields = response["Attribute"]
                for field_key in attribute_fields:
                    if filter_fields and field_key not in shown_fields:
                        continue
                    prefix = self.prefix if self.prefix else ""
                    record[prefix + field_key] = response["Attribute"][field_key]

            yield record

if __name__ == "__main__":
    dispatch(MispGetAttributeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
