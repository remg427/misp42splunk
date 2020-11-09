# coding=utf-8
#
# collect attributes or events as events in Splunk
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

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
import time
from splunklib.six.moves import map
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(retainsevents=True, type='events', distributed=False)
class MispRestCommand(GeneratingCommand):
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
    method = Option(
        doc='''
        **Syntax:** **method=****
        **Description:** method to use for API target DELETE GET PATCH POST.''',
        require=True, validate=validators.Match("method", r"^(DELETE|GET|POST)$"))
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***JSON request*
        **Description:** JSON-formatted json_request.''',
        require=False, validate=validators.Match("json_request", r"^{.+}$"))
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search;
         default 1000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("page", r"^[0-9]+$"))
    target = Option(
        doc='''
        **Syntax:** **target=api_target****
        **Description:**target of MISP API.''',
        require=True, validate=validators.Match("target", r"^/(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+$"))


    def generate(self):

        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        my_args = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if my_args is None:
            raise Exception("Sorry, no configuration for misp_instance={}".format(misp_instance))
        my_args['host'] = my_args['misp_url'].replace('https://', '')
        if self.target not in [None, '']:
            my_args['misp_url'] = my_args['misp_url'] + self.target
        if self.json_request not in [None, '']:
            body_dict = json.loads(self.json_request)
            logging.debug('[MR-201] body_dict is {}'.format(body_dict))
        else:
            body_dict = {}

        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['misp_key']
        headers['Accept'] = 'application/json'
        if self.method == "GET":
            r = requests.get(my_args['misp_url'],
                             headers=headers,
                             params=body_dict,
                             verify=my_args['misp_verifycert'],
                             cert=my_args['client_cert_full_path'],
                             proxies=my_args['proxies'])
        elif self.method == "POST":
            r = requests.post(my_args['misp_url'],
                              headers=headers,
                              data=json.dumps(body_dict),
                              verify=my_args['misp_verifycert'],
                              cert=my_args['client_cert_full_path'],
                              proxies=my_args['proxies'])
        elif self.method == "DELETE":
            r = requests.delete(my_args['misp_url'],
                                headers=headers,
                                verify=my_args['misp_verifycert'],
                                cert=my_args['client_cert_full_path'],
                                proxies=my_args['proxies'])
        else:
            raise Exception(
                "Sorry, no valid method provided (GET/POST//DELETE)."
                " it was {}.".format(self.method)
            )

        # check if status is anything other than 200;
        # throw an exception if it is
        if r.status_code in (200, 201, 204):
            logging.info(
                "[RE301] INFO mispcollect successful. "
                "url={}, HTTP status={}".format(my_args['misp_url'], r.status_code)
            )
        else:
            logging.error(
                "[RE302] ERROR mispcollect failed. "
                "url={}, data={}, HTTP Error={}, content={}"
                .format(my_args['misp_url'], body_dict, r.status_code, r.text)
            )
            raise Exception(
                "[RE302] ERROR mispcollect failed. "
                "url={}, data={}, HTTP Error={}, content={}"
                .format(my_args['misp_url'], body_dict, r.status_code, r.text)
            )
        # response is 200 by this point or we would have thrown an exception
        data = {'_time': time.time(), '_raw': json.dumps(r.json())}
        yield data


if __name__ == "__main__":
    # set up custom logger for the app commands
    logging.root
    loglevel = logging_level('misp42splunk')
    logging.root.setLevel(loglevel)
    logging.error('logging level is set to %s', loglevel)
    logging.error('PYTHON VERSION: ' + sys.version)
    dispatch(MispRestCommand, sys.argv, sys.stdin, sys.stdout, __name__)
