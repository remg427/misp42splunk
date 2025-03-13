
# coding=utf-8

#
# Create Events in MISP from results of alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
from __future__ import print_function
from misp_common import prepare_config, urllib_init_pool, urllib_request
import csv
import datetime
import gzip
import json
import os
import re
import time
import splunklib.client as client
from io import open

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "5.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"

# encoding = utf-8

def is_uuid_v4(field):
    uuid_v4_pattern = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    return bool(uuid_v4_pattern.match(field))

def get_datatype_dict(helper, config, app_name):
    datatype_dict = dict()
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    directory = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name, 'lookups'
    )
    dt_filename = os.path.join(directory, 'misp_datatypes.csv')
    if os.path.exists(dt_filename):
        try:
            # open the file with gzip lib, start making alerts
            # can with statements fail gracefully??
            fh = open(dt_filename, "rt")
        except ValueError:
            # Workaround for Python 2.7 under Windows
            fh = gzip.open(dt_filename, "r")
        if fh is not None:
            try:
                csv_reader = csv.DictReader(fh)
                for row in csv_reader:
                    if 'field_name' in row and 'field_type' in row:
                        if row['field_type'] == 'attribute':
                            datatype_dict[row['field_name']] = row['datatype']
                helper.log_info("[HC304] datatype_dict built from misp_datatypes.csv")
            except IOError:  # file misp_datatypes.csv not readable
                helper.log_error('[HC305] file {} empty, malformed or not readable'.format(
                    dt_filename
                ))
    return datatype_dict


def prepare_alert(helper, app_name):
    # Get parameters for calling prepare_config
    instance = helper.get_param("misp_instance")
    sessionKey = helper.settings['session_key']
    splunkService = client.connect(token=sessionKey)
    storage = splunkService.storage_passwords
    helper.log_debug("[AL-PA-D01] successfully retrieved storage object")
    config_args = prepare_config(helper, app_name, instance, storage, sessionKey)
    if config_args is None:
        return None

    alert_args = {
        'tlp': str(helper.get_param("tlp").replace('_', ':')),
        'pap': str(helper.get_param("pap").replace('_', ':')),
        'eventid': str(helper.get_param("eventid") or "0"),
        'eventkey': str(helper.get_param("unique") or "singleEvent"),
        'info': str(helper.get_param("info") or "notable event"),
        'published': helper.get_param("publish_on_creation") == "1",
        'tags': str(helper.get_param("tags")) if helper.get_param("tags") else None,
        'analysis': int(helper.get_param("analysis")),
        'threatlevel': int(helper.get_param("threatlevel")),
        'distribution': int(helper.get_param("distribution"))
    }
    config_args.update(alert_args)

    return config_args


def init_object_template(helper, ot):
    try:
        # open object definition.json
        _SPLUNK_PATH = os.environ['SPLUNK_HOME']
        # open misp.conf
        object_definition = os.path.join(
            _SPLUNK_PATH, 'etc', 'apps', 'misp42splunk',
            'bin', ot + '_definition.json')
        with open(object_definition) as json_object:
            od = json.load(json_object)
        return od
    except IOError:
        helper.log_error("[AL-IOT-E01] file not found {}".format(object_definition))
        return None


def store_object_attribute(object_attributes, t, v, metadata=None):
    Attribute = metadata
    if t in object_attributes:
        Attribute['type'] = object_attributes[t]['misp-attribute']
        Attribute['object_relation'] = t
        Attribute['value'] = v
    return Attribute


def prepare_misp_events(helper, config, event_list):
    events = {}
    event_baseline = {
        'threat_level_id': config['threatlevel'],
        'analysis': config['analysis'],
        'distribution': config['distribution'],
        'published': config['published'],
        'Attribute': [],
        'Object': []
    }

    data_type = get_datatype_dict(helper, config, 'misp42splunk')
    tags = [{'name': config['tlp']}, {'name': config['pap']}]
    if config['tags']:
        tags.extend({'name': tag} for tag in config['tags'].split(',') if tag not in tags)
    event_baseline['Tag'] = tags

    results = helper.get_events()
    for row in results:
        row = {key: value for key, value in row.items() if not key.startswith("__mv_")}
        # Get the specific eventkey if defined in Splunk search.
        eventkey = str(row.get(config['eventkey'], config['eventkey']))
        # Get the specific eventid if defined in Splunk search.
        eventid = str(row.pop(config['eventid'], config['eventid']))
        # Check if eventid contains only digits or a uuid v4
        if not (re.match(r'^\d+$', eventid) or is_uuid_v4(eventid)):
            eventid = "0"
        helper.log_info(f"[AL-PPE-I01] eventkey is {eventkey} and eventid is {eventid}")

        if eventkey in events:
            event = events[eventkey]
            row.pop('misp_date', None)
            row.pop('misp_info', None)
        else:
            event_list[eventkey] = eventid
            event = event_baseline.copy()
            event['date'] = datetime.datetime.fromtimestamp(
                int(row.pop('misp_date', time.time()))).strftime('%Y-%m-%d')
            event['info'] = row.pop('misp_info', config['info'])

        if config['distribution'] == 4:
            if 'misp_sg_id' in row:
                event['sharing_group_id'] = int(row.pop('misp_sg_id', 0))
            else:
                helper.log_error("[AL-PPE-E01] Distribution is set to Sharing Group but no field misp_sg_id is provided")
            
        attributes = list(event['Attribute'])
        objects = list(event['Object'])

        tags = list(event['Tag'])
        if 'misp_tag' in row:
            tags.extend({'name': tag} for tag in row.pop('misp_tag').split(',') if tag not in tags)
        event['Tag'] = tags

        event['published'] = row.pop('misp_publish_on_creation', "0") == "1"

        attribute_baseline = dict()
        # collect attribute value and build type=value entry
        if 'misp_attribute_tag' in row:
            attribute_baseline['Tag'] = [{'name': tag} for tag in row.pop('misp_attribute_tag', '').split(',') if tag]

        if 'misp_category' in row:
            attribute_baseline['category'] = str(row.pop('misp_category'))

        if 'misp_comment' in row:
            attribute_baseline['comment'] = str(row.pop('misp_comment'))

        if 'misp_to_ids' in row:
            attribute_baseline['to_ids'] = row.pop('misp_to_ids', 'False') == 'True',

        if 'misp_first_seen' in row:  # must be EPOCH UNIX
            attribute_baseline['first_seen'] = datetime.datetime.fromtimestamp(
                int(row.pop('misp_first_seen'))).strftime('%Y-%m-%dT%H:%M:%S.%f%z')

        if 'misp_last_seen' in row:  # must be EPOCH UNIX
            attribute_baseline['last_seen'] = datetime.datetime.fromtimestamp(
                int(row.pop('misp_last_seen'))).strftime('%Y-%m-%dT%H:%M:%S.%f%z')

        # now we take KV pairs starting by misp_
        # to add to event as attributes(s) of an object
        # or as single attribute(s)
        # 

        fo_template = init_object_template(helper, 'file')
        eo_template = init_object_template(helper, 'email')
        no_template = init_object_template(helper, 'domain-ip')
        fo_attribute, eo_attribute, no_attribute = [], [], []

        for key, value in row.items():
            for single in str(value).split("\n"):
                if single.strip() and single != '0':
                    attribute_metadata = attribute_baseline.copy()
                    if key.startswith("misp_"):
                        attribute_metadata['type'] = key.replace('misp_', '').replace('_', '-')
                        attribute_metadata['value'] = single
                        attributes.append(attribute_metadata)
                    elif key.startswith("fo_"):
                        object_attribute = store_object_attribute(
                            fo_template['attributes'], key.replace('fo_', '').replace('_', '-'), single, metadata=attribute_metadata)
                        if object_attribute:
                            fo_attribute.append(object_attribute)
                    elif key.startswith("eo_"):
                        object_attribute = store_object_attribute(
                            eo_template['attributes'], key.replace('eo_', '').replace('_', '-'), single, metadata=attribute_metadata)
                        if object_attribute:
                            eo_attribute.append(object_attribute)
                    elif key.startswith("no_"):
                        object_attribute = store_object_attribute(
                            no_template['attributes'], key.replace('no_', '').replace('_', '-'), single, metadata=attribute_metadata)
                        if object_attribute:
                            no_attribute.append(object_attribute)
                    elif key in data_type:
                        attribute_metadata['type'] = data_type[key]
                        attribute_metadata['value'] = single
                        attributes.append(attribute_metadata)

        event['Attribute'] = attributes

        def add_misp_object(object_template, object_attributes):
            if object_attributes:
                objects.append({
                    'template_version': object_template['version'],
                    'description': object_template['description'],
                    'meta-category': object_template['meta-category'],
                    'template_uuid': object_template['uuid'],
                    'name': object_template['name'],
                    'distribution': 5,
                    'Attribute': object_attributes
                })

        add_misp_object(fo_template, fo_attribute)
        add_misp_object(eo_template, eo_attribute)
        add_misp_object(no_template, no_attribute)

        event['Object'] = objects
        events[eventkey] = event

    return events


def process_misp_events(helper, config, results, event_list):
    connection, connection_status = urllib_init_pool(helper, config)

    def handle_response(response, success_msg, error_msg):
        if '_raw' not in response:
            helper.log_info(success_msg)
        else:
            helper.log_error(error_msg.format(response))

    for eventkey, event in results.items():
        helper.log_debug(f"[AL-PME-D01] payload is {event}")
        if event_list[eventkey] == "0":  # create new event
            misp_url_create = f"{config['misp_url']}/events/add"
            response = urllib_request(
                helper, 
                connection, 
                'POST', 
                misp_url_create, 
                event, 
                config
                ) if connection else connection_status
            handle_response(response, 
                f"[AL-PME-I02] INFO MISP event is successfully created. url={misp_url_create}",
                f"[AL-PME-E01] ERROR MISP event creation has failed. url={misp_url_create}, response={{}}"
                )
        else:  # edit existing eventid with Attribute and Object
            misp_url_edit = f"{config['misp_url']}/events/edit/{event_list[eventkey]}"
            edit_body = {'Attribute': event['Attribute'], 'Object': event['Object']}
            response = urllib_request(
                helper, 
                connection, 
                'POST', 
                misp_url_edit, 
                edit_body, 
                config
                ) if connection else connection_status
            handle_response(response, 
                f"[AL-PME-I04] INFO MISP event is successfully edited. url={misp_url_edit}",
                f"[AL-PME-E02] ERROR MISP event edition has failed. url={misp_url_edit}, response={{}}"
                )


def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the alert action parameters
    # and prints them to the log
    title = helper.get_param("title")
    helper.log_info("title={}".format(title))

    description = helper.get_param("description")
    helper.log_info("description={}".format(description))

    eventid = helper.get_param("eventid")
    helper.log_info("eventid={}".format(eventid))

    unique = helper.get_param("unique")
    helper.log_info("unique={}".format(unique))

    info = helper.get_param("info")
    helper.log_info("info={}".format(info))

    distribution = helper.get_param("distribution")
    helper.log_info("distribution={}".format(distribution))

    threatlevel = helper.get_param("threatlevel")
    helper.log_info("threatlevel={}".format(threatlevel))

    analysis = helper.get_param("analysis")
    helper.log_info("analysis={}".format(analysis))

    tlp = helper.get_param("tlp")
    helper.log_info("tlp={}".format(tlp))

    pap = helper.get_param("pap")
    helper.log_info("pap={}".format(pap))

    tags = helper.get_param("tags")
    helper.log_info("tags={}".format(tags))

    misp_instance = helper.get_param("misp_instance")
    helper.log_info("misp_instance={}".format(misp_instance))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.set_log_level(helper.log_level)
    helper.log_info("[AL-PE-I01] Alert action misp_alert_create_event started.")

    misp_app_name = "misp42splunk"
    misp_config = prepare_alert(helper, misp_app_name)
    if misp_config is None:
        helper.log_error("[AL-PE-E01] FATAL config dict not initialised")
        # data = {
        #     '_time': time.time(),
        #     '_raw': json.loads("AL-PE-E01] FATAL config dict not initialised")
        # }
        # yield data
        return 1
    else:
        helper.log_info("[AL-PE-I02] config dict is ready to use")
        event_list = {}
        events = prepare_misp_events(helper, misp_config, event_list)
        if events is not None:
            helper.log_info("[AL-PE-I03] Events dict is ready to use")
            process_misp_events(helper, misp_config, events, event_list)
            helper.log_info("[AL-PE-I04] Alert action misp_alert_create_event completed")
        else:
            helper.log_error("[AL-PE-E02] FATAL no event to process")
            return 2
    return 0
