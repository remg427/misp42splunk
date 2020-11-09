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
from splunklib.six.moves import map
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


@Configuration(retainsevents=True, type='events', distributed=False)
class MispCollectCommand(GeneratingCommand):
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
        **Description:**starting date.
         **eventid**, **last** and **date** are mutually exclusive''',
        require=False)
    # Other params
    category = Option(
        doc='''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for.
         Wildcard is %.''',
        require=False)
    endpoint = Option(
        doc='''
        **Syntax:** **endpoint=***<events|attributes>*
        **Description:**selection of MISP API restSearch endpoint.
        **default**: /attributes/restSearch''',
        require=False, validate=validators.Match("endpoint", r"(events|attributes)"))
    geteventtag = Option(
        doc='''
        **Syntax:** **geteventtag=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean includeEventTags. By default only
         attribute tag(s) are returned.''',
        require=False, validate=validators.Boolean())
    keep_related = Option(
        doc='''
        **Syntax:** **keep_related=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to keep related events.
        default is to drop  RelatedEvents to reduce volume.''',
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
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("page", r"^[0-9]+$"))
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

    @staticmethod
    def _record(serial_number, time_stamp, host, attributes, attribute_names, encoder):

        raw = encoder.encode(attributes)
        # Formulate record
        fields = dict()
        for f in attribute_names:
            if f in attributes:
                fields[f] = attributes[f]

        if serial_number > 0:
            fields['_serial'] = serial_number
            fields['_time'] = time_stamp
            fields['_raw'] = raw
            fields['host'] = host
            return fields

        record = OrderedDict(chain(
            (('_serial', serial_number), ('_time', time_stamp),
             ('_raw', raw), ('host', host)),
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
            raise Exception('Missing "json_request", "eventid", "last" or "date" argument')
        elif mandatory_arg > 1:
            raise Exception('Options "json_request", "eventid", "last" and "date" are mutually exclusive')

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
        body_dict['deleted'] = False
        body_dict['includeEventUuid'] = True
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

        # Search parameters: boolean and filter
        # manage to_ids and enforceWarninglist
        # to avoid FP enforceWarninglist is set to True if
        # to_ids is set to True (search criterion)
        if self.category is not None:
            if "," in self.category:
                cat_criteria = {}
                cat_list = self.category.split(",")
                cat_criteria['OR'] = cat_list
                body_dict['category'] = cat_criteria
            else:
                body_dict['category'] = self.category
        if self.endpoint == 'events':
            my_args['misp_url'] = my_args['misp_url'] + '/events/restSearch'
        else:
            my_args['misp_url'] = my_args['misp_url'] + '/attributes/restSearch'
        if self.geteventtag is True:
            body_dict['includeEventTags'] = True
        if self.keep_related is True:
            keep_related = True
        else:
            keep_related = False
        if self.to_ids is True:
            body_dict['to_ids'] = True
            body_dict['enforceWarninglist'] = True  # protection
        elif self.to_ids is False:
            body_dict['to_ids'] = False
        if self.type is not None:
            if "," in self.type:
                type_criteria = {}
                type_list = self.type.split(",")
                type_criteria['OR'] = type_list
                body_dict['type'] = type_criteria
            else:
                body_dict['type'] = self.type
        if self.warning_list is True:
            body_dict['enforceWarninglist'] = True
        elif self.warning_list is False:
            body_dict['enforceWarninglist'] = False
        if self.tags is not None or self.not_tags is not None:
            tags_criteria = {}
            if self.tags is not None:
                tags_list = self.tags.split(",")
                tags_criteria['OR'] = tags_list
            if self.not_tags is not None:
                tags_list = self.not_tags.split(",")
                tags_criteria['NOT'] = tags_list
            body_dict['tags'] = tags_criteria

        if pagination is True:
            body_dict['page'] = page
            body_dict['limit'] = limit

        body = json.dumps(body_dict)
        logging.debug('mispgetioc request body: %s', body)
        # search
        r = requests.post(my_args['misp_url'], headers=headers, data=body,
                          verify=my_args['misp_verifycert'],
                          cert=my_args['client_cert_full_path'],
                          proxies=my_args['proxies'])
        # check if status is anything other than 200;
        # throw an exception if it is
        if r.status_code in (200, 201, 204):
            logging.info(
                "[CO301] INFO mispcollect successful. "
                "url={}, HTTP status={}".format(my_args['misp_url'], r.status_code)
            )
        else:
            logging.error(
                "[CO302] ERROR mispcollect failed. "
                "url={}, data={}, HTTP Error={}, content={}"
                .format(my_args['misp_url'], body, r.status_code, r.text)
            )
            raise Exception(
                "[CO302] ERROR mispcollect failed. "
                "url={}, data={}, HTTP Error={}, content={}"
                .format(my_args['misp_url'], body, r.status_code, r.text)
            )
        # response is 200 by this point or we would have thrown an exception
        response = r.json()
        encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))
        if self.endpoint == "events":
            if 'response' in response:
                for r_item in response['response']:
                    if 'Event' in r_item:
                        attribute_names = []
                        serial_number = 0
                        for e in list(r_item.values()):
                            if keep_related is False:
                                e.pop('RelatedEvent', None)
                            if serial_number == 0:
                                for k in list(e.keys()):
                                    attribute_names.append(k)
                            yield MispCollectCommand._record(
                                serial_number, e['timestamp'], my_args['host'],
                                e, attribute_names, encoder)
                        serial_number += 1
                        GeneratingCommand.flush
        else:
            if 'response' in response:
                if 'Attribute' in response['response']:
                    attribute_names = []
                    serial_number = 0
                    for a in response['response']['Attribute']:
                        if serial_number == 0:
                            for k in list(a.keys()):
                                attribute_names.append(k)
                        yield MispCollectCommand._record(
                            serial_number, a['timestamp'], my_args['host'],
                            a, attribute_names, encoder)
                        serial_number += 1
                        GeneratingCommand.flush


if __name__ == "__main__":
    # set up custom logger for the app commands
    logging.root
    loglevel = logging_level('misp42splunk')
    logging.root.setLevel(loglevel)
    logging.error('logging level is set to %s', loglevel)
    logging.error('PYTHON VERSION: ' + sys.version)
    dispatch(MispCollectCommand, sys.argv, sys.stdin, sys.stdout, __name__)
