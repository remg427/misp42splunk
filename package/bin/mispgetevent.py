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
from splunklib.searchcommands import dispatch, GeneratingCommand, Configuration, Option, validators
import sys
import json
import logging
from misp_common import prepare_config, generate_record, logging_level, urllib_init_pool, get_events, map_event_table, splunk_timestamp

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "5.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


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
    # status
    {
        "returnFormat": forced to json,
        "page": param,
        "limit": param,
        "value": not managed,
        "type": param,
        "category": param,
        "org": not managed,
        "tag": not managed,
        "tags": param, see also not_tags
        "event_tags": not managed,
        "searchall": not managed,
        "date": param,
        "last": param,
        "eventid": param,
        "withAttachments": forced to False,
        "metadata": not managed,
        "uuid": not managed,
        "published": param,
        "publish_timestamp": param,
        "timestamp": param,
        "enforceWarninglist": param,
        "sgReferenceOnly": not managed,
        "eventinfo": not managed,
        "sharinggroup": not managed,
        "excludeLocalTags": not managed,
        "threat_level_id": param
    }
    """
    # MANDATORY MISP instance for this search
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=** *instance_name*
        **Description:** MISP instance parameters as described in local/misp42splunk_instances.conf.
        ''',
        require=True
    )
    # MANDATORY: json_request XOR eventid XOR last XOR date
    json_request = Option(
        doc='''
        **Syntax:** **json_request=** *valid JSON request*
        **Description:** valid JSON request - see MISP REST API endpoint attributes/ restSearch
        ''',
        require=False,
        validate=validators.Match("json_request", r"^{.+}$")
    )
    date = Option(
        doc='''
        **Syntax:** **date=** *The user set event date field*
        **Description:** the user set date field at event level.The date format follows ISO 8061.
        ''',
        require=False,
        validate=validators.Match("date", r"^[0-9\-,d]+$")
    )
    eventid = Option(
        doc='''
        **Syntax:** **eventid=** *id1(,id2,...)*
        **Description:** list of event ID(s) or event UUID(s).
        ''',
        require=False,
        validate=validators.Match("eventid", r"^[0-9a-f,\-]+$")
    )
    last = Option(
        doc='''
        **Syntax:** **last=** *<int>d|h|m*
        **Description:** events published within the **last** x amount of time, 
        where x can be defined in (d)ays, (h)ours, (m)inutes 
        (for example 5d or 12h or 30m), ISO 8601 datetime format or timestamp.
        **nota bene:** last is an alias of published_timestamp
        ''',
        require=False,
        validate=validators.Match("last", r"^(\d+[hdm]|\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})$")
    )
    publish_timestamp = Option(
        doc='''
        **Syntax:** **publish_timestamp=** *<int>d|h|m*
        **Description:** relative publication duration in day(s), hour(s) or minute(s).
        ''',
        require=False,
        validate=validators.Match("last", r"^(\d+[hdm]|\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})$")
    )
    timestamp = Option(
        doc='''
        **Syntax:** **timestamp=** *<int>d|h|m*
        **Description:** event timestamp (last change).
        ''',
        require=False,
        validate=validators.Match("last", r"^(\d+[hdm]|\d+|\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})$")
    )
    # Other params for MISP REST API
    category = Option(
        doc='''
        **Syntax:** **category=** *CSV string*
        **Description:** comma(,)-separated string of categories. Wildcard is %.
        ''',
        require=False
    )
    exclude_local_tags = Option(
        doc='''
        **Syntax:** **exclude_local_tagss=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** Boolean excludeLocalTags.
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    include_sightings = Option(
        doc='''
        **Syntax:** **include_sightings=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** Boolean includeSightings. Extend response with Sightings DB 
        results if the module is enabled
        **Default:** True
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )
    limit = Option(
        doc='''
        **Syntax:** **limit=** *<int>*
        **Description:** define the limit for each MISP search. 0 = no pagination.
        **Default:** 1000
        ''',
        require=False, 
        default=1000,
        validate=validators.Integer()
    )
    not_tags = Option(
        doc='''
        **Syntax:** **not_tags=** *CSV string*
        **Description:** comma(,)-separated string of tags to exclude. Wildcard is %.
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
        default=0,
        validate=validators.Integer()
    )
    published = Option(
        doc='''
        **Syntax:** **published=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**select only published events (for option from to).
        ''',
        require=False,
        validate=validators.Boolean()
    )
    tags = Option(
        doc='''
        **Syntax:** **tags=** *CSV string*
        **Description:** comma(,)-separated string of tags to search for. Wildcard is %.
        ''',
        require=False
    )
    threat_level_id = Option(
        doc='''
        **Syntax:** **threat_level_id=***<int>*
        **Description:**define the threat level (1-High, 2-Medium, 3-Low, 4-Undefined).
        ''',
        require=False,
        validate=validators.Match("limit", r"^[1-4]$")
    )
    to_ids = Option(
        doc='''
        **Syntax:** **to_ids=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean to search only attributes with the flag
         "to_ids" set to true.
        ''',
        require=False,
        validate=validators.Boolean()
    )
    type = Option(
        doc='''
        **Syntax:** **type=** *CSV string*
        **Description:** comma(,)-separated string of types to search for. Wildcard is %.
        ''',
        require=False
    )
    warning_list = Option(
        doc='''
        **Syntax:** **warning_list=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean to filter out well known values.
        **Default:** True
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    ) 
    # Other params to process the attributes and prepare the results
    expand_object = Option(
        doc='''
        **Syntax:** **gexpand_object=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean to have object attributes expanded (one per line).
        **Default:** False, attributes of an object are displayed on same line.
        ''',
        require=False, 
        default=False,
        validate=validators.Boolean()
    )
    getioc = Option(
        doc='''
        **Syntax:** **getioc=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return the list of attributes together with the event.
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    keep_galaxy = Option(
        doc='''
        **Syntax:** **keep_galaxy=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to keep or remove key Galaxy (useful with output=json)
        **Default:** True
        ''',
        require=False, 
        default=True,
        validate=validators.Boolean()
    )
    keep_related = Option(
        doc='''
        **Syntax:** **keep_galaxy=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to remove related events per attribute (useful with output=json)
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    output = Option(
        doc='''
        **Syntax:** **output=** *<fields|json>*
        **Description:** selection between the default Splunk tabular view - output=fields - or JSON - output=json.
        **Default:** fields
        ''',
        require=False,
        default='fields', 
        validate=validators.Match("output", r"(fields|json)")
    )
    pipesplit = Option(
        doc='''
        **Syntax:** **pipesplit=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean to split multivalue attributes.
        **Default:** True
        ''',
        require=False, 
        default=True, 
        validate=validators.Boolean()
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

    def generate(self):
        # loggging
        self.set_log_level()
        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        config = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if config is None:
            raise Exception(
                "[EV-101] Sorry, no configuration for misp_instance={}".format(misp_instance))
        config['misp_url'] = config['misp_url'] + '/events/restSearch'

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
            self.log_error('[EV-102] Missing "date", "eventid", "json_request", "last", "publish_timestamp" or "timestamp" argument')
            raise Exception('[EV-102] Missing "date", "eventid", "json_request", "last", "publish_timestamp" or "timestamp" argument')
        elif mandatory_arg > 1:
            self.log_error('[EV-103] Options "date", "eventid", "json_request", "last", "publish_timestamp" or "timestamp" are mutually exclusive')
            raise Exception('[EV-103] Options "date", "eventid", "json_request", "last", "publish_timestamp" or "timestamp" are mutually exclusive')

        body_dict = dict()
        # Only ONE combination was provided
        if self.json_request is not None:
            body_dict = json.loads(self.json_request)
            self.log_info('[EV-204] Option "json_request" set')
        elif self.eventid:
            if "," in self.eventid:
                event_criteria = {}
                event_list = self.eventid.split(",")
                event_criteria['OR'] = event_list
                body_dict['eventid'] = event_criteria
            else:
                body_dict['eventid'] = self.eventid
            self.log_info('[EV-205] Option "eventid" set with {}'.format(json.dumps(body_dict['eventid'])))
        elif self.last:
            body_dict['last'] = self.last
            self.log_info('[EV-206] Option "last" set with {}'.format(body_dict['last']))
        elif self.publish_timestamp is not None:
            if "," in self.publish_timestamp:  # contain a range
                publish_list = self.publish_timestamp.split(",")
                body_dict['publish_timestamp'] = [str(publish_list[0]),
                                                  str(publish_list[1])]
            else:
                body_dict['publish_timestamp'] = self.publish_timestamp
            self.log_info('[EV-207] Option "publish_timestamp " {}'.format(json.dumps(body_dict['publish_timestamp'])))
        elif self.timestamp is not None:
            if "," in self.timestamp:  # contain a range
                timestamp_list = self.timestamp.split(",")
                body_dict['timestamp'] = [str(timestamp_list[0]),
                                          str(timestamp_list[1])]
            else:  # contain a timestamp EPOCH or relative time
                body_dict['timestamp'] = self.timestamp
            self.log_info('[EV-208] Option "timestamp" {}'.format(json.dumps(body_dict['timestamp'])))
        else:  # implicit param date
            if "," in self.date:  # string should contain a range
                date_list = self.date.split(",")
                body_dict['date'] = [str(date_list[0]), str(date_list[1])]
            else:
                body_dict['date'] = self.date
            self.log_info('[EV-209] Option "date range" key date {}'.format(json.dumps(body_dict['date'])))

        # Force some values on JSON request
        body_dict['returnFormat'] = 'json'
        body_dict['withAttachments'] = False

        # Search pagination
        config['limit'] = int(body_dict.get('limit', self.limit))
        config['page'] = int(body_dict.get('page', self.page))

        self.log_info('[EV-301] limit {} page {}'.format(config['limit'],config['page']))

        # set REST http body key having a default value
        body_dict['excludeLocalTags'] = body_dict.get('excludeLocalTags', self.exclude_local_tags)
        body_dict['enforceWarninglist'] = body_dict.get('enforceWarninglist', self.warning_list)

        # set REST http body keys without default value
        if self.category and 'category' not in body_dict:
            if "," in self.category:
                cat_criteria = {}
                cat_list = self.category.split(",")
                cat_criteria['OR'] = cat_list
                body_dict['category'] = cat_criteria
            else:
                body_dict['category'] = self.category

        if self.published is not None:
            body_dict['published'] = body_dict.get('published', self.published)

        if self.to_ids is not None:
            body_dict['to_ids'] = body_dict.get('to_ids', self.to_ids)

        if self.type and 'type' not in body_dict:
            if "," in self.type:
                type_criteria = {}
                types = self.type.split(",")
                type_criteria['OR'] = types
                body_dict['type'] = type_criteria
            else:
                body_dict['type'] = self.type

        if (self.tags or self.not_tags) and 'tags' not in body_dict:
            tags_criteria = {}
            if self.tags:
                tags_list = self.tags.split(",")
                tags_criteria['OR'] = tags_list
            if self.not_tags:
                tags_list = self.not_tags.split(",")
                tags_criteria['NOT'] = tags_list
            body_dict['tags'] = tags_criteria

        if self.threat_level_id:
            body_dict['threat_level_id'] = self.threat_level_id

        # output filter parameters
        config['expand_object'] = self.expand_object
        config['getioc'] = self.getioc
        config['include_sightings'] = body_dict.get('includeSightingdb', self.include_sightings)
        config['keep_galaxy'] = self.keep_galaxy
        config['keep_related'] = self.keep_related
        config['output'] = self.output
        config['pipesplit'] = self.pipesplit
        if self.prefix:
            config['prefix'] = self.prefix

        connection, connection_status = urllib_init_pool(self, config)
        if connection is None:
            response = connection_status
            self.log_info('[EV-401] connection for {} failed'.format(config['misp_url']))
            yield response
        else:
            response_list = get_events(self, connection, config, body_dict)
            self.log_info('[EV-402] response_list: {}'.format(len(response_list)))
            # response contains results
            # if output=json, returns JSON objects
            if config['output'] == "json":
                for e in response_list:
                    splunk_ts = splunk_timestamp(e.get('timestamp'))
                    yield generate_record(
                        e,
                        time=splunk_ts,
                        generator=self
                    )
            else:
                output_list = map_event_table(self, response_list, config)
                for result in output_list:
                    splunk_ts = splunk_timestamp(result.get('misp_timestamp'))
                    yield generate_record(
                        result,
                        time=splunk_ts,
                        generator=self
                    )


if __name__ == "__main__":
    dispatch(MispGetEventCommand, sys.argv, sys.stdin, sys.stdout, __name__)
