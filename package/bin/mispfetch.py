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
import logging
from misp_common import prepare_config, logging_level, urllib_init_pool, generate_record, get_attributes, map_attribute_table, get_events, map_event_table, splunk_timestamp
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators
from splunklib.six.moves import map
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
__version__ = "5.0.0"
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
        **Description:**MISP instance parameters as described in local/misp42splunk_instances.conf.
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
        **Syntax:** **keep_galaxy=** *<1|y|Y|t|true|True|0|n|N|f|false|False>*
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
        **Default:** False
        ''',
        require=False,
        default=False,
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
            v[f'{prefix}timestamp'] = int(v[f'{prefix}timestamp'])
            # append attribute tags to tag list
            tag_list = list()
            if 'Tag' in a:
                for tag in a['Tag']:
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
            'attribute_count': 'analysis_count',
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
            event_org = e.get('Org')
            for org_key, org_value in event_org.items():
                event_dict[f'{prefix}org_{org_key}'] = org_value
            event_orgc = e.get('Orgc')
            for orgc_key, orgc_value in event_orgc.items():
                event_dict[f'{prefix}org_{orgc_key}'] = orgc_value

            event_dict[f'{prefix}timestamp'] = event_dict[f'{prefix}event_timestamp']
            event_dict[f'{prefix}host'] = host
            event_dict[f'{prefix}json'] = copy.deepcopy(e)
            event_json_list.append(event_dict)

        return event_json_list

    def stream(self, records):
        self.set_log_level()

        config = dict()
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
                    config['misp_url'] = config['misp_url'] + '/events/restSearch'
                elif mf_params['misp_restsearch'] == "attributes":
                    config['misp_url'] = config['misp_url'] + '/attributes/restSearch'
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

                if 'includeSightings' in body_dict:
                    config['include_sightings'] = body_dict['includeSightings']
                elif 'includeSightingdb' in body_dict:
                    config['include_sightings'] = body_dict['includeSightingdb']
                else:
                    config['include_sightings'] = True  # default true whithout additional param

                self.log_info('[MF-100] actual http body: {} '.format(json.dumps(body_dict)))

                connection, connection_status = urllib_init_pool(self, config)
                if connection is None:
                    response = connection_status
                    self.log_info('[MF-200] connection for {} failed'.format(config['misp_url']))
                    yield response
                else:
                    output_list = []
                    if mf_params['misp_restsearch'] == "events":
                        response_list = get_events(self, connection, config, body_dict)
                        event_list = list()
                        if config['misp_output_mode'] == "json":
                            event_list = self.map_event_json(response_list, config)
                        else:
                            event_list = map_event_table(self, response_list, config)

                        for event in event_list:
                            event['misp_mispfetch_params'] = mf_params
                            output_list.append(event)

                    else:  # misp_restsearch=="attributes"
                        response_list = get_attributes(self, connection, config, body_dict)
                        attribute_list = list()
                        if config['misp_output_mode'] == "json":
                            attribute_list = self.map_attribute_json(response_list, config)
                        else:
                            attribute_list = map_attribute_table(self, response_list, config)

                        for attribute in attribute_list:
                            attribute['misp_mispfetch_params'] = mf_params
                            output_list.append(attribute)

                    if output_list is not None:
                        for result in output_list:
                            splunk_ts = splunk_timestamp(result.get('misp_timestamp'))
                            yield generate_record(
                                result,
                                time=splunk_ts,
                                generator=self
                            )


if __name__ == "__main__":
    dispatch(MispFetchCommand, sys.argv, sys.stdin, sys.stdout, __name__)
