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
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import sys
import logging
from misp_common import prepare_config, urllib_request, logging_level, urllib_init_pool

__author__ = "timothebot"
__license__ = "LGPLv3"
__version__ = "6.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(distributed=False)
class MispGetAttributeCommand(StreamingCommand):
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=** *instance_name*
        **Description:** MISP instance parameters as described in 
        local/misp42splunk_instances.conf.
        ''',
        require=True
    )
    attributeid = Option(
        doc='''
        **Syntax:** **attributeid=** *<fieldname>*
        **Description:** Fieldname containing the ID of attribute to check
        ''',
        require=True,
        validate=validators.Fieldname())
    output_filter = Option(
        doc='''
        **Syntax:** **output_filter=** *CSV string*
        **Description:** comma(,)-separated string of MISP JSON keys to use. 
        Default is all keys.
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
        # logging.root
        loglevel = logging_level(self.service, 'misp42splunk')
        logging.root.setLevel(loglevel)
        logging.error('[AT-101] logging level is set to %s', loglevel)
        logging.debug('[AT-102] PYTHON VERSION: ' + sys.version)

    def stream(self, records):
        self.set_log_level()
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        config = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if config is None:
            self.log_error(f"[AT-201] Sorry, no configuration for {misp_instance}")
        base_url = config['misp_url'] + "/attributes/view/"

        shown_fields = []
        if self.output_filter:
            shown_fields = self.output_filter.replace(" ", "").split(",")
        filter_fields = len(shown_fields) > 0
        if self.prefix:
            config['prefix'] = self.prefix

        prefix = config.get('prefix', "misp_")

        for record in records:
            if self.attributeid in record:
                attribute_id = record[self.attributeid]
                if not str(attribute_id).isdigit():
                    self.log_warn(f"[AT-202]Invalid attribute ID: {attribute_id}")
                    yield record
                    continue

                config['misp_url'] = base_url + str(attribute_id)

                connection, connection_status = urllib_init_pool(self, config)
                if connection is None:
                    response = connection_status
                    self.log_error('[AT-202] connection failed')
                    record[f"{prefix}error_message"] = connection_status
                else:
                    response, response_size = urllib_request(
                        self, 
                        connection, 
                        "GET", 
                        config['misp_url'],
                        {},
                        config)
                    if not isinstance(response, dict):
                        self.log_warn("[AT-203] Unexpected response format")
                        yield record
                        continue

                    if "Attribute" in response:
                        attribute_fields = response["Attribute"]
                        for key, value in attribute_fields.items():
                            if not filter_fields or key in shown_fields:
                                record[f"{prefix}{key}"] = value

            yield record


if __name__ == "__main__":
    dispatch(MispGetAttributeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
