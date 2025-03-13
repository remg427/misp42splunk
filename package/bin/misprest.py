# coding=utf-8
#
# collect attributes or events as events in Splunk
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

from __future__ import absolute_import, division, print_function, unicode_literals
import misp42splunk_declare

import json
import logging
from misp_common import prepare_config, logging_level, urllib_init_pool, urllib_request
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import time
import sys

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "5.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(distributed=False)
class MispRestCommand(GeneratingCommand):
    # MANDATORY MISP instance
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=** *instance_name*
        **Description:** MISP instance parameters as described in local/misp42splunk_instances.conf.
        ''',
        require=True
    )
    method = Option(
        doc='''
        **Syntax:** **method=****
        **Description:** method to use for API target DELETE GET POST PUT.
        **Default:** GET.
        ''',
        require=False,
        default="GET",
        validate=validators.Match("method", r"^(DELETE|GET|POST|PUT)$")
    )
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***JSON request*
        **Description:** JSON-formatted json_request.
        ''',
        require=False, 
        validate=validators.Match("json_request", r"^{.+}$")
    )
    target = Option(
        doc='''
        **Syntax:** **target=api_target****
        **Description:** target of MISP API.
        **Default:** /servers/serverSettings
        ''',
        require=False, 
        default="/servers/serverSettings",
        validate=validators.Match("target", r"^/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$")
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
        logging.error('[MR-201] logging level is set to %s', loglevel)
        logging.error('[MR-202] PYTHON VERSION: ' + sys.version)

    def generate(self):
        # loggging
        self.set_log_level()
        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        config = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if config is None:
            raise Exception("[MR-101] Sorry, no configuration for misp_instance={}".format(misp_instance))

        try:
            body_dict = json.loads(self.json_request)
        except Exception:
            body_dict = {}
        config['method'] = self.method
        config['misp_url'] = config['misp_url'] + self.target

        connection, connection_status = urllib_init_pool(self, config)
        if connection is None:
            response = connection_status
            self.log_info('[MR-102] connection for {} failed'.format(config['misp_url']))
            yield response
        else:
            response = urllib_request(self, connection, config['method'], config['misp_url'], body_dict, config)
            # response is 200 by this point or we would have thrown an exception
            data = {'_time': time.time(), '_raw': json.dumps(response)}
            yield data


if __name__ == "__main__":
    dispatch(MispRestCommand, sys.argv, sys.stdin, sys.stdout, __name__)
