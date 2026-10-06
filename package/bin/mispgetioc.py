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
import sys
import json
from misp_common import prepare_config, generate_record, logging_level, urllib_init_pool, iter_attribute_pages, iter_attribute_table, order_groups_by_event, map_attribute_table, misp_bool, prefixed, splunk_timestamp, create_output_budget, log_truncation_summary, CommandMessage, message_field

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "6.1.0"
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
    decay_score_threshold = Option(
        doc='''
        **Syntax:** **decay_score_threshold=** *<int>*
        **Description:** define the minimum sore to override on-the-fly the threshold of the decaying model.
        ''',
        require=False,
        validate=validators.Match("decay_score_threshold", r"^[0-9]+$")
    )
    decaying_model = Option(
        doc='''
        **Syntax:** **decaying_model=** *<int>*
        **Description:** ID of the decaying model to select specific model.
        ''',
        require=False,
        validate=validators.Match("decaying_model", r"^[0-9]+$")
    )
    exclude_decayed = Option(
        doc='''
        **Syntax:** **exclude_decayed=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean to exclude decayed attributes.
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    geteventtag = Option(
        doc='''
        **Syntax:** **geteventtag=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean includeEventTags.
        **Default:** True, event tags are returned in addition of any attribute tags.
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    )
    include_decay_score = Option(
        doc='''
        **Syntax:** **include_decay_score=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean to return decay sores.
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    include_deleted = Option(
        doc='''
        **Syntax:** **include_deleted=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** Boolean include_deleted.
        **Default:** False - only non deleted attribute are returned.
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
    order = Option(
        doc='''
        **Syntax:** **order=** *CSV string*
        **Description:** sort order for /attributes/restSearch, as
        "Model.field [asc|desc]" rules separated by commas.
        MISP applies no ORDER BY unless asked, and paginating an unordered query
        with limit/page can return overlapping or missing rows across pages, so a
        stable sort is required for a multi-page fetch to be correct.
        Ordering by event_id first also lets results be streamed page by page:
        attributes of one event stay contiguous, so no merged object row is split
        across a page boundary.
        MISP 2.5 accepts these fields only: Attribute.id, Attribute.event_id,
        Attribute.object_id, Attribute.type, Attribute.category,
        Attribute.value, Attribute.distribution, Attribute.timestamp,
        Attribute.object_relation and Event.publish_timestamp.
        Set to "none" to send no order; results are then buffered in full before
        being returned.
        **Default:** Attribute.event_id,Attribute.id
        ''',
        require=False,
        default='Attribute.event_id,Attribute.id'
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
        **Description:** boolean to filter out well known values. Ignored when
         to_ids=true, which always enforces the warninglist; set
         enforceWarninglist in json_request to override that.
        **Default:** True
        ''',
        require=False,
        default=True,
        validate=validators.Boolean()
    ) 
    # Other params to process the attributes and prepare the results
    expand_object = Option(
        doc='''
        **Syntax:** **expand_object=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:** boolean to have object attributes expanded (one per line).
        **Default:** False, attributes of an object are displayed on same line.
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
        self.logger.error(msg)

    def log_info(self, msg):
        self.logger.info(msg)

    def log_debug(self, msg):
        self.logger.debug(msg)

    def log_warn(self, msg):
        self.logger.warning(msg)

    def set_log_level(self):
        loglevel = logging_level(self.service, 'misp42splunk')
        self.logger.setLevel(loglevel)
        self.logger.info('[IO-201] logging level is set to %s', loglevel)
        self.logger.info('[IO-202] PYTHON VERSION: %s', sys.version)

    def generate(self):
        # loggging
        self.set_log_level()

        # Phase 1: Preparation
        misp_instance = self.misp_instance
        storage = self.service.storage_passwords
        config = prepare_config(self, 'misp42splunk', misp_instance, storage)
        if config is None:
            raise Exception("[IO-101] Sorry, no configuration for misp_instance={}".format(misp_instance))
        config['misp_url'] = config['misp_url'] + '/attributes/restSearch'

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
            self.log_info('[IO-105] Option "eventid" set with {}'.format(json.dumps(body_dict['eventid'])))
        elif self.last:
            body_dict['last'] = self.last
            self.log_info('[IO-106] Option "last" set with {}'.format(body_dict['last']))
        elif self.publish_timestamp:
            if "," in self.publish_timestamp:  # contain a range
                publish_list = self.publish_timestamp.split(",")
                body_dict['publish_timestamp'] = [str(publish_list[0]),
                                                  str(publish_list[1])]
            else:
                body_dict['publish_timestamp'] = self.publish_timestamp
            self.log_info('[IO-107] Option "publish_timestamp" set with {}'.format(body_dict['publish_timestamp']))
        elif self.timestamp:
            if "," in self.timestamp:  # contain a range
                timestamp_list = self.timestamp.split(",")
                body_dict['timestamp'] = [str(timestamp_list[0]),
                                          str(timestamp_list[1])]
            else:  # contain a timestamp EPOCH or relative time
                body_dict['timestamp'] = self.timestamp
            self.log_info('[IO-108] Option "timestamp" set with {}'.format(body_dict['timestamp']))
        else:  # implicit param date
            if "," in self.date:  # string should contain a range
                date_list = self.date.split(",")
                body_dict['date'] = [str(date_list[0]), str(date_list[1])]
            else:
                body_dict['date'] = self.date
            self.log_info('[IO-109] Option "date range" key date {}'.format(json.dumps(body_dict['date'])))

        # Force some values on JSON request
        body_dict['returnFormat'] = 'json'
        body_dict['withAttachments'] = False
        body_dict['includeEventUuid'] = True

        # Search pagination
        config['limit'] = int(body_dict.get('limit', self.limit))
        config['page'] = int(body_dict.get('page', self.page))

        self.log_info('[IO-201] limit {} page {}'.format(config['limit'], config['page']))

        # Search parameters: boolean and filter

        # set REST http body key having a default value
        body_dict['deleted'] = body_dict.get('deleted', self.include_deleted)
        # Noted before the default is applied: after this line the key is always
        # present, and the to_ids safeguard below must not override a choice the
        # user spelled out in json_request.
        warninglist_in_request = 'enforceWarninglist' in body_dict
        body_dict['enforceWarninglist'] = body_dict.get('enforceWarninglist', self.warning_list)
        body_dict['includeEventTags'] =  body_dict.get('includeEventTags', self.geteventtag)

        # fetchAttributes() leaves $params['order'] empty unless asked, so
        # restSearch paginates with LIMIT/OFFSET over an unordered set: pages can
        # overlap and skip. Ordering by event_id also lets
        # iter_attribute_table() stream (see order_groups_by_event()).
        # An explicit order in json_request always wins; order=none opts out.
        if 'order' not in body_dict and self.order \
           and str(self.order).lower() != 'none':
            body_dict['order'] = self.order
            self.log_info(
                '[IO-110] Option "order" set to {} for stable pagination'
                .format(body_dict['order']))

        # set REST http body keys without default value
        if self.category and 'category' not in body_dict:
            if "," in self.category:
                cat_criteria = {}
                cat_list = self.category.split(",")
                cat_criteria['OR'] = cat_list
                body_dict['category'] = cat_criteria
            else:
                body_dict['category'] = self.category

        if (self.tags or self.not_tags) and 'tags' not in body_dict:
            tags_criteria = {}
            if self.tags:
                tags_list = self.tags.split(",")
                tags_criteria['OR'] = tags_list
            if self.not_tags:
                tags_list = self.not_tags.split(",")
                tags_criteria['NOT'] = tags_list
            body_dict['tags'] = tags_criteria

        if self.to_ids is not None:
            body_dict['to_ids'] = body_dict.get('to_ids', self.to_ids)

        # to_ids=true selects the attributes a publisher meant to feed
        # detection, so a warninglist hit among them is a likely false positive
        # (RFC1918 ranges, public resolvers, heavily visited domains). Those are
        # the values that generate alert storms once the results reach a lookup
        # or a correlation search, so the warninglist is enforced even when
        # warning_list=false asked otherwise.
        # An explicit enforceWarninglist in json_request still wins.
        if misp_bool(body_dict.get('to_ids')) \
           and not warninglist_in_request \
           and not misp_bool(body_dict['enforceWarninglist']):
            body_dict['enforceWarninglist'] = True
            self.log_warn(
                '[IO-111] key enforceWarninglist forced to True because '
                'to_ids is true: warninglisted values are likely false '
                'positives. Set enforceWarninglist in json_request to '
                'override')

        if self.type and 'type' not in body_dict:
            if "," in self.type:
                type_criteria = {}
                types = self.type.split(",")
                type_criteria['OR'] = types
                body_dict['type'] = type_criteria
            else:
                body_dict['type'] = self.type

        if self.threat_level_id:
            body_dict['threat_level_id'] = body_dict.get('threat_level_id', self.threat_level_id)

        # Decaying Model related Search parameters
        if self.include_decay_score is not None:
            body_dict['includeDecayScore'] = body_dict.get('includeDecayScore', self.include_decay_score)
        if self.exclude_decayed is not None:
            body_dict['excludeDecayed'] = body_dict.get('excludeDecayed', self.exclude_decayed)
        if self.decaying_model:
            body_dict['decayingModel'] = body_dict.get('decayingModel', self.decaying_model)
        if self.decay_score_threshold:
            body_dict['score'] = body_dict.get('score', self.decay_score_threshold)        

        # output filter parameters
        config['expand_object'] = self.expand_object
        config['include_sightings'] = body_dict.get('includeSightings', self.include_sightings)
        config['output'] = self.output
        config['pipesplit'] = self.pipesplit
        if self.prefix:
            config['prefix'] = self.prefix

        connection, connection_status = urllib_init_pool(self, config)
        if connection is None:
            response = connection_status
            self.log_info('[IO-204] connection for {} failed'.format(config['misp_url']))
            yield response
        else:
            # Carries totals and any truncation reason into the result set as
            # <prefix>mispgetioc_message.
            message = CommandMessage(message_field(config, 'mispgetioc'))
            pages = iter_attribute_pages(
                self, connection, config, body_dict, message=message)

            if config['output'] == "json":
                # Raw MISP attributes, so the key is unprefixed here.
                # No merging either, so pages stream straight through.
                rows = (a for page in pages for a in page)
                ts_key = 'timestamp'
            elif order_groups_by_event(body_dict):
                # Event-ordered: map a page at a time, carrying the trailing
                # event over so no merged group is split.
                rows = iter_attribute_table(self, pages, config)
                ts_key = prefixed(config, 'timestamp')
            else:
                # Without event ordering a merged group may straddle a page
                # boundary, so the whole set has to be mapped at once.
                rows = map_attribute_table(
                    self, [a for page in pages for a in page], config)
                ts_key = prefixed(config, 'timestamp')

            # splunklib buffers every record until generate() returns and cannot
            # flush partial chunks, so maxresultrows gives no back-pressure.
            # Bound what we produce instead.
            budget = create_output_budget(config, logger=self.logger)
            for result in rows:
                record = generate_record(
                    message.stamp(result),
                    event_time=splunk_timestamp(result.get(ts_key)),
                    generator=self
                )
                yield record
                if budget.consume(record):
                    break

            self.log_info(
                '[IO-206] yielded {} record(s)'.format(budget.rows))
            budget.log_summary(self, message=message)
            log_truncation_summary(self, message=message)


if __name__ == "__main__":
    dispatch(MispGetIocCommand, sys.argv, sys.stdin, sys.stdout, __name__)
