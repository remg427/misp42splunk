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
from itertools import chain
import json
from misp_common import LimitChecker, create_limit_checker, prepare_config, logging_level, urllib_init_pool, generate_record, iter_attribute_pages, iter_attribute_table, order_groups_by_event, map_attribute_table, iter_event_pages, map_event_table, prefixed, splunk_timestamp, create_output_budget, log_truncation_summary, CommandMessage, message_field
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
import sys
import copy

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

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "6.1.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


MISPFETCH_INIT_PARAMS = {
    # mandatory parameter for mispfetch
    'misp_instance': None,
    # optional parameters for request
    'misp_restsearch': 'events',
    'misp_http_body': None,
    'getioc': False,
    'limit': 1000,
    'page': 0,
    'not_tags': None,
    'order': 'Attribute.event_id,Attribute.id',
    'tags': None,
    # optional parameters to format results
    'attribute_limit': 0,
    'expand_object': False,
    'misp_output_mode': 'fields',
    'keep_galaxy': False,
    'keep_related': False,
    'pipesplit': True,
    'prefix': 'misp_'}


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
        **Description:**MISP instance parameters as described in \
        local/misp42splunk_instances.conf.
         ''',
        require=False
    )
    misp_restsearch = Option(
        doc='''
        **Syntax:** misp_restsearch=<string>
        **Description:**define the restSearch endpoint.Either "events" or "attributes". 
        **Default:** events
        ''',
        require=False,
        default="events",
        validate=validators.Match("misp_restsearch", r"^(events|attributes)$")
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
        **Default:** fields
        ''',
        require=False,
        default="fields",
        validate=validators.Match("misp_output_mode", r"^(fields|json)$")
    )
    attribute_limit = Option(
        doc='''
        **Syntax:** attribute_limit=<int>
        **Description:**define the attribute_limit for max count of
         returned attributes for each MISP default; 0 = no limit.
        **Default:** 0
        ''',
        require=False, 
        default=0,
        validate=validators.Integer()
    )
    expand_object = Option(
        doc='''
        **Syntax:** expand_object=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to expand object attributes one per line.
        By default, attributes of one object are displayed on same line.
        **Default:** False
        ''',
        require=False, 
        default=False,
        validate=validators.Boolean()
    )
    getioc = Option(
        doc='''
        **Syntax:** getioc=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to return the list of attributes together with the event.
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    keep_galaxy = Option(
        doc='''
        **Syntax:** keep_galaxy=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to remove galaxy part (useful with misp_output_mode=json)
        ''',
        require=False, 
        default=False,
        validate=validators.Boolean()
    )
    keep_related = Option(
        doc='''
        **Syntax:** **keep_related=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to remove related events per attribute (useful with output=json)
        **Default:** False
        ''',
        require=False,
        default=False,
        validate=validators.Boolean()
    )
    limit = Option(
        doc='''
        **Syntax:** limit=<int>
        **Description:**define the limit for each request to MISP. 0 = no pagination.
        **Default:** 1000
        ''',
        require=False,
        default=1000,
        validate=validators.Integer()
    )
    not_tags = Option(
        doc='''
        **Syntax:** not_tags=<string>,<string>*
        **Description:**Comma(,)-separated string of tags to exclude. Wildcard is %.
        ''',
        require=False
    )
    order = Option(
        doc='''
        **Syntax:** order=<string>
        **Description:**sort order for misp_restsearch=attributes, as
        "Model.field [asc|desc]" rules separated by commas. MISP applies no
        ORDER BY unless asked, and paginating an unordered query with limit/page
        can return overlapping or missing rows across pages, so a stable sort is
        required for a multi-page fetch to be correct.
        Ignored for misp_restsearch=events, whose sortable fields are different.
        Ordering by event_id first also lets results be streamed page by page:
        attributes of one event stay contiguous, so no merged object row is split
        across a page boundary.
        MISP 2.5.x accepts these fields only: Attribute.id, Attribute.event_id,
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
    pipesplit = Option(
        doc='''
        **Syntax:** pipesplit=<1|y|Y|t|true|True|0|n|N|f|false|False>
        **Description:**Boolean to split multivalue attributes.
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
        **Default:** misp_
        ''',
        require=False, 
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
        self.logger.info('[MF-101] logging level is set to %s', loglevel)
        self.logger.info('[MF-102] PYTHON VERSION: %s', sys.version)

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

    def map_attribute_json(self, input_json, config):
        attribute_mapping = {
            'category': 'category',
            'comment': 'comment',
            'deleted': 'deleted',
            'distribution': 'attribute_distribution',
            'event_id': 'event_id',
            'event_uuid': 'event_uuid',
            'first_seen': 'first_seen',
            'id': 'attribute_id',
            'last_seen': 'last_seen',
            'object_id': 'object_id',
            'object_relation': 'object_relation',
            'sharing_group_id': 'sharing_group_id',
            'timestamp': 'timestamp',
            'to_ids': 'to_ids',
            'type': 'type',
            'uuid': 'attribute_uuid',
            'value': 'value',
        }

        attribute_json_list = list()
        host = config.get('host', "unknown")
        prefix = config.get('prefix', "misp_")
        for a in input_json:
            v = dict()
            # prepend key names with misp_attribute_
            for key, value in attribute_mapping.items():
                if key in a:
                    v[f'{prefix}{value}'] = a[key]
            # Both absent on some attributes, so neither is dereferenced
            # directly. Tag can also arrive as a single dict.
            ts_field = f'{prefix}timestamp'
            if ts_field in v:
                try:
                    v[ts_field] = int(v[ts_field])
                except (TypeError, ValueError):
                    pass
            tag_list = list()
            tag_value = a.get('Tag')
            if isinstance(tag_value, dict):
                tag_value = [tag_value]
            if isinstance(tag_value, list):
                for tag in tag_value:
                    try:
                        tag_list.append(str(tag['name']))
                    except Exception:
                        pass
            v[f'{prefix}host'] = host
            v[f'{prefix}tag'] = tag_list
            # include Event metatdata
            if 'Event' in a:
                e = a['Event']
                event_mapping = {
                    'distribution': 'event_distribution',
                    'id': 'event_id',
                    'info': 'event_info',
                    'org_id': 'org_id',
                    'orgc_id': 'orgc_id',
                    'publish_timestamp': 'publish_timestamp',
                    'uuid': 'event_uuid',
                }
                for key, value in event_mapping.items():
                    if key in e:
                        v[f'{prefix}{value}'] = e[key]

            v[f'{prefix}json'] = a
            attribute_json_list.append(v)

        return attribute_json_list

    def map_event_json(self, input_json, config):
        # build output table and list of types
        event_json_list = list()
        host = config.get('host',"unknown_host")
        prefix = config.get('prefix', "misp_")
        # process events and return a list of dict
        # if getioc=true each event entry contains a key Attribute
        # with a list of all attributes
        event_mapping = {
            'analysis': 'analysis', 
            'attribute_count': 'attribute_count',
            'date': 'event_date',
            'disable_correlation': 'disable_correlation',
            'distribution': 'distribution', 
            'extends_uuid': 'extends_uuid', 
            'id': 'event_id',
            'info': 'event_info',
            'locked': 'locked', 
            'proposal_email_lock': 'proposal_email_lock', 
            'publish_timestamp': 'publish_timestamp',
            'published': 'event_published',
            'sharing_group_id': 'sharing_group_id', 
            'threat_level_id': 'threat_level_id', 
            'timestamp': 'event_timestamp',
            'uuid': 'event_uuid',
            'value': 'value',
        }
        for e in input_json:
            event_dict = dict()
            for key, value in event_mapping.items():
                if key in e:
                    event_dict[f'{prefix}{value}'] = e[key]
            # Absent or null on some events, so never dereferenced directly.
            # Orgc goes under orgc_, as map_event_table() does: sharing org_
            # made the creator overwrite the owner and dropped orgc_ entirely.
            event_org = e.get('Org') or {}
            for org_key, org_value in event_org.items():
                event_dict[f'{prefix}org_{org_key}'] = org_value
            event_orgc = e.get('Orgc') or {}
            for orgc_key, orgc_value in event_orgc.items():
                event_dict[f'{prefix}orgc_{orgc_key}'] = orgc_value

            # Left unset when the event carries no timestamp; the caller then
            # falls back to search time instead of raising.
            if f'{prefix}event_timestamp' in event_dict:
                event_dict[f'{prefix}timestamp'] = \
                    event_dict[f'{prefix}event_timestamp']
            event_dict[f'{prefix}host'] = host
            event_dict[f'{prefix}json'] = copy.deepcopy(e)
            event_json_list.append(event_dict)

        return event_json_list

    def stream(self, records):
        self.set_log_level()

        config = dict()
        record = None
        for record in records:
            yield record

        if record:
            self.log_debug('[MF-010] self.metadata {}'.format(self.metadata))
            if self.metadata.finished:
                # extract parameters from last record from input set
                # Phase 1: Preparation
                mf_params = self.create_mf_params(record)
                self.log_info('[MF-050] mf_params {}'.format(mf_params))

                if mf_params['misp_instance'] is None:
                    raise Exception(
                        "Sorry, self.mf_params['misp_instance'] is not defined")
                storage = self.service.storage_passwords
                config = prepare_config(self,
                                        'misp42splunk',
                                        mf_params['misp_instance'],
                                        storage)
                if config is None:
                    raise Exception(
                        "Sorry, no configuration for misp_instance={}"
                        .format(mf_params['misp_instance']))
                config.update(mf_params)

                if mf_params['misp_restsearch'] == "events":
                    config['misp_url'] = config['misp_url'] \
                        + '/events/restSearch'
                elif mf_params['misp_restsearch'] == "attributes":
                    config['misp_url'] = config['misp_url'] \
                        + '/attributes/restSearch'
                self.log_info(
                    '[MF-030] misp_instance {} restSearch {} url {}'
                    .format(config['misp_instance'],
                            config['misp_restsearch'],
                            config['misp_url']))
                if config['misp_http_body'] is None:
                    # Force some values on JSON request
                    body_dict = dict()
                    body_dict['last'] = "1h"
                    body_dict['published'] = True
                else:
                    body_dict = dict(json.loads(config['misp_http_body']))
                # enforce returnFormat to JSON
                body_dict['returnFormat'] = 'json'
                body_dict['withAttachments'] = False

                # Without metadata MISP serialises every Attribute, which
                # _prune_event() discards on arrival: the transfer is paid for
                # nothing and large result sets hit max_response_size_mb before
                # the last page. Events endpoint only - the attributes endpoint
                # never reads getioc.
                # An explicit "metadata" in misp_http_body always wins.
                if config['misp_restsearch'] == "events":
                    if mf_params['getioc'] is False \
                       and 'metadata' not in body_dict:
                        body_dict['metadata'] = 1
                        self.log_info(
                            '[MF-103] getioc is false; key metadata set to 1 '
                            'to fetch event metadata only')
                    # MISP bug (2.5.33): fetchEvent() unsets the Attribute
                    # container under metadata, but its warninglist block still
                    # passes $event['Attribute'] to
                    # attachWarninglistToAttributes(array &$attrs) - null
                    # against an array type, so the request dies with HTTP 500.
                    # Both flags only filter attributes, which metadata does not
                    # return, so disabling them is free.
                    if body_dict.get('metadata'):
                        for flag in ('enforceWarninglist',
                                     'includeWarninglistHits'):
                            if body_dict.get(flag):
                                body_dict[flag] = False
                                self.log_warn(
                                    f'[MF-104] key {flag} forced to False: it '
                                    'is incompatible with metadata and makes '
                                    'MISP return HTTP 500')

                    # Same principle as metadata: do not transfer structures
                    # that _prune_event() discards. Galaxy clusters are attached
                    # in full by default server-side.
                    if mf_params['keep_galaxy'] is False \
                       and 'excludeGalaxy' not in body_dict:
                        body_dict['excludeGalaxy'] = 1
                        self.log_info(
                            '[MF-105] keep_galaxy is false; key excludeGalaxy '
                            'set to 1 so MISP does not attach galaxy clusters')

                    # includeEventCorrelations is not in
                    # Event::$possibleOptions, so MISP 2.5.33 drops it and
                    # RelatedEvent still arrives. Sent anyway: harmless, and
                    # correct if MISP ever accepts it.
                    if mf_params['keep_related'] is False \
                       and 'includeEventCorrelations' not in body_dict:
                        body_dict['includeEventCorrelations'] = 0
                        self.log_info(
                            '[MF-106] keep_related is false; requesting '
                            'includeEventCorrelations=0 (ignored by MISP '
                            '2.5.33, so RelatedEvent is still transferred '
                            'and then discarded)')
                    # Under metadata MISP returns no Attribute, so
                    # attribute-level output is impossible whatever getioc asked
                    # for.
                    config['getioc'] = (
                        mf_params['getioc'] and not body_dict.get('metadata'))

                else:  # misp_restsearch=="attributes"
                    # fetchAttributes() leaves $params['order'] empty unless
                    # asked, so restSearch paginates with LIMIT/OFFSET over an
                    # unordered set: pages can overlap and skip. Attributes
                    # endpoint only - the events endpoint has other sortable
                    # fields and would reject Attribute.*.
                    # An explicit order in misp_http_body always wins;
                    # order=none opts out.
                    order = mf_params['order']
                    if 'order' not in body_dict and order \
                       and str(order).lower() != 'none':
                        body_dict['order'] = order
                        self.log_info(
                            '[MF-108] order set to {} for stable pagination'
                            .format(order))

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
                if self.prefix:
                    config['prefix'] = self.prefix

                if 'includeSightings' in body_dict:
                    config['include_sightings'] = body_dict['includeSightings']
                elif 'includeSightingdb' in body_dict:
                    config['include_sightings'] = body_dict['includeSightingdb']
                else:
                    config['include_sightings'] = False  # default False whithout additional param

                self.log_info('[MF-100] actual http body: {} '.format(json.dumps(body_dict)))

                connection, connection_status = urllib_init_pool(self, config)
                if connection is None:
                    response = connection_status
                    self.log_info('[MF-200] connection for {} failed'.format(config['misp_url']))
                    yield response
                else:
                    # splunklib buffers every record until stream() returns and
                    # cannot flush partial chunks, so the budget is what keeps
                    # this terminating.
                    budget = create_output_budget(config, logger=self.logger)
                    # Reports totals and any truncation reason as
                    # <prefix>mispfetch_message. The events branch streams, so
                    # there the last records carry the most complete message.
                    message = CommandMessage(
                        message_field(config, 'mispfetch'))
                    # Every mapper on both branches prefixes its keys, so these
                    # names have to be derived, not spelled out.
                    ts_key = prefixed(config, 'timestamp')
                    params_key = prefixed(config, 'mispfetch_params')

                    if mf_params['misp_restsearch'] == "events":
                        # One page at a time, so peak memory follows limit rather
                        # than the whole result set. Both mappers are safe per
                        # page: map_event_json() is per-event pure, and
                        # map_event_table() only merges records within one
                        # event's own attribute list, never across events.
                        # The generator is single-pass - do not call len() on it.
                        for page in iter_event_pages(
                            self, connection, config, body_dict,
                            message=message
                        ):
                            if config['misp_output_mode'] == "json":
                                rows = self.map_event_json(page, config)
                            else:
                                rows = map_event_table(self, page, config)

                            for result in rows:
                                result[params_key] = mf_params
                                record = generate_record(
                                    message.stamp(result),
                                    event_time=splunk_timestamp(
                                        result.get(ts_key)),
                                    generator=self
                                )
                                yield record
                                if budget.consume(record):
                                    break
                            if budget.exhausted:
                                break

                    else:  # misp_restsearch=="attributes"
                        pages = iter_attribute_pages(
                            self, connection, config, body_dict,
                            message=message)
                        if config['misp_output_mode'] == "json":
                            # Per-attribute mapping, so pages stream through.
                            attribute_list = (
                                row
                                for page in pages
                                for row in self.map_attribute_json(page, config)
                            )
                        elif order_groups_by_event(body_dict):
                            # Event-ordered: map a page at a time, carrying the
                            # trailing event over so no merged group is split.
                            attribute_list = iter_attribute_table(
                                self, pages, config)
                        else:
                            # Without event ordering a merged group may straddle
                            # a page boundary, so map the whole set at once.
                            attribute_list = map_attribute_table(
                                self, [a for page in pages for a in page],
                                config)

                        for result in attribute_list:
                            result[params_key] = mf_params
                            record = generate_record(
                                message.stamp(result),
                                event_time=splunk_timestamp(
                                    result.get(ts_key)),
                                generator=self
                            )
                            yield record
                            if budget.consume(record):
                                break

                    self.log_info(
                        '[MF-107] yielded {} record(s)'.format(budget.rows))
                    budget.log_summary(self, message=message)
                    log_truncation_summary(self, message=message)


if __name__ == "__main__":
    dispatch(MispFetchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
