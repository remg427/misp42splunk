
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
import time
import splunklib.client as client
from io import open

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.2.1"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"

#
# most of the code here was based on the following
# example on splunk custom alert event_list
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample


# encoding = utf-8

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
    alert_args = dict()
    # Get string values from alert form
    alert_args['tlp'] = str(helper.get_param("tlp").replace('_', ':'))
    alert_args['pap'] = str(helper.get_param("pap").replace('_', ':'))
    if not helper.get_param("eventid"):
        alert_args['eventid'] = "0"
    else:
        alert_args['eventid'] = str(helper.get_param("eventid"))
    if not helper.get_param("unique"):
        alert_args['eventkey'] = "oneEvent"
    else:
        alert_args['eventkey'] = str(helper.get_param("unique"))
    if not helper.get_param("info"):
        alert_args['info'] = "notable event"
    else:
        alert_args['info'] = str(helper.get_param("info"))
    published = helper.get_param("publish_on_creation")
    if published == "1":
        alert_args['published'] = True
    else:
        alert_args['published'] = False
    if not helper.get_param("tags"):
        alert_args['tags'] = None
    else:
        alert_args['tags'] = str(helper.get_param("tags"))
    # Get numeric values from alert form
    alert_args['analysis'] = int(helper.get_param("analysis"))
    alert_args['threatlevel'] = int(helper.get_param("threatlevel"))
    alert_args['distribution'] = int(helper.get_param("distribution"))

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
    # print(config)
    # iterate through each row, cleaning multivalue fields and then adding
    # the attributes under same event key
    # this builds the dict events
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
    # tag the event with TLP level
    tags = [{'name': config['tlp']}, {'name': config['pap']}]
    # Add tags set in alert definition
    if config['tags'] is not None:
        tag_list = config['tags'].split(',')
        for tag in tag_list:
            if tag not in tags:
                new_tag = {'name': tag}
                tags.append(new_tag)
    event_baseline['Tag'] = tags

    results = helper.get_events()
    for row in results:
        # Splunk makes a bunch of dumb empty multivalue fields
        # - we filter those out here
        row = {key: value for key, value in list(row.items())
               if not key.startswith("__mv_")}

        # Get the specific eventkey if defined in Splunk search.
        # Defaults to alert form value
        eventkey = config['eventkey']
        if eventkey in row:
            eventkey = str(row[eventkey])
        helper.log_info("[AL-PPE-I01] eventkey is {}".format(eventkey))

        # Get the specific eventid if define in Splunk search.
        # Defaults to alert form value
        # Value == 0: means create new event
        # Value <> 0: edit existing event
        eventid = config['eventid']  # from the alert conf
        if eventid in row:         # overwrites from the result row
            eventid = str(row.pop(eventid))
        helper.log_info("[AL-PPE-I02] eventid is {}".format(eventid))

        # check if building event has been initiated
        # if yes simply add attribute entry otherwise collect other metadata
        # remove fields misp_time and info from row
        # if this is a new event: 
        # keep info from first row for the first row of that eventkey
        # keep misp_time as event date for the first row of that eventkey
        attribute_baseline = dict()

        if eventkey in events:
            event = events[eventkey]
            if 'misp_time' in row: # drop any misp_time in row 2 to n
                row.pop('misp_time')
            if 'misp_info' in row:  # drop any misp_info in row 2 to n
                row.pop('misp_info')
        else:
            event_list[eventkey] = eventid
            event = event_baseline.copy()
            if 'misp_time' in row:
                event['date'] = datetime.datetime.fromtimestamp(
                    int(row.pop('misp_time'))).strftime('%Y-%m-%d')
            else:
                event['date'] = datetime.datetime.fromtimestamp(
                    int(time.time())).strftime('%Y-%m-%d')

            if 'misp_info' in row: 
                event['info'] = row.pop('misp_info')
            else:
                event['info'] = config['info']

        if config['distribution'] == 4:
            if 'misp_sg_id' in row:
                event['sharing_group_id'] = int(
                    row.pop('misp_sg_id'))  # "sharing_group_id"
            else:
                helper.log_error("Distribution is set to Sharing Group but no field misp_sg_id is provided")
        attributes = list(event['Attribute'])
        objects = list(event['Object'])
        tags = list(event['Tag'])

        # Update event metadata
        # append event tags provided in the row
        if 'misp_tag' in row:
            tag_list = row.pop('misp_tag').split(',')
            for tag in tag_list:
                if tag not in tags:
                    new_tag = {'name': tag}
                    tags.append(new_tag)
        # update event tag list
        event['Tag'] = list(tags)

        if 'misp_publish_on_creation' in row:
            publish_on_creation = str(row.pop('misp_publish_on_creation'))
            if publish_on_creation == "1":
                event['published'] = True
            elif publish_on_creation == "0":
                event['published'] = False

        # collect attribute value and build type=value entry
        if 'misp_attribute_tag' in row:
            att_tags = []
            att_tag_list = str(row.pop('misp_attribute_tag')).split(',')
            for atag in att_tag_list:
                if atag not in att_tags:
                    new_tag = {'name': atag}
                    att_tags.append(new_tag)
            # update event tag list
            attribute_baseline['Tag'] = att_tags 

        if 'misp_category' in row:
            attribute_baseline['category'] = str(row.pop('misp_category'))

        if 'misp_comment' in row:
            attribute_baseline['comment'] = str(row.pop('misp_comment'))

        if 'misp_to_ids' in row:
            if str(row.pop('misp_to_ids')) == 'True':
                attribute_baseline['to_ids'] = True
            else:
                attribute_baseline['to_ids'] = False

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
        fo_attribute = []
        eo_template = init_object_template(helper, 'email')
        eo_attribute = []
        no_template = init_object_template(helper, 'domain-ip')
        no_attribute = []
        for key, value in list(row.items()):
            if '\n' in value: # was a multivalue field
                values = value.splitlines()
            else:
                values = value.split()

            for v in values:
                attribute_metadata = attribute_baseline.copy()
                if key.startswith("misp_") and v not in [None, '']:
                    misp_key = str(key).replace('misp_', '').replace('_', '-')
                    attribute_metadata['type'] = misp_key
                    attribute_metadata['value'] = str(v)
                    attributes.append(attribute_metadata)
                elif key.startswith("fo_") and v not in [None, '']:
                    fo_key = str(key).replace('fo_', '').replace('_', '-')
                    object_attribute = store_object_attribute(
                        fo_template['attributes'], fo_key, str(v),
                        metadata=attribute_metadata)
                    if object_attribute:
                        fo_attribute.append(object_attribute)
                elif key.startswith("eo_") and v not in [None, '']:
                    eo_key = str(key).replace('eo_', '').replace('_', '-')
                    object_attribute = store_object_attribute(
                        eo_template['attributes'], eo_key, str(v),
                        metadata=attribute_metadata)
                    if object_attribute:
                        eo_attribute.append(object_attribute)
                elif key.startswith("no_") and v not in [None, '']:
                    no_key = str(key).replace('no_', '').replace('_', '-')
                    object_attribute = store_object_attribute(
                        no_template['attributes'], no_key, str(v),
                        metadata=attribute_metadata)
                    if object_attribute:
                        no_attribute.append(object_attribute)
                elif key in data_type:
                    misp_key = data_type[key]
                    attribute_metadata['type'] = misp_key
                    attribute_metadata['value'] = str(v)
                    attributes.append(attribute_metadata)

        # update event attribute list
        event['Attribute'] = list(attributes)

        # now we look for attribute belonging to anobject i.e.
        # on the same row, field(s) start(s) with no_, eo_ or no_
        if fo_attribute:
            new_object = {
                'template_version': fo_template['version'],
                'description': fo_template['description'],
                'meta-category': fo_template['meta-category'],
                'template_uuid': fo_template['uuid'],
                'name': fo_template['name'],
                'distribution': 5,
                'Attribute': fo_attribute
            }
            objects.append(new_object)
        if eo_attribute:
            new_object = {
                'template_version': eo_template['version'],
                'description': eo_template['description'],
                'meta-category': eo_template['meta-category'],
                'template_uuid': eo_template['uuid'],
                'name': eo_template['name'],
                'distribution': 5,
                'Attribute': eo_attribute
            }
            objects.append(new_object)
        if no_attribute:
            new_object = {
                'template_version': no_template['version'],
                'description': no_template['description'],
                'meta-category': no_template['meta-category'],
                'template_uuid': no_template['uuid'],
                'name': no_template['name'],
                'distribution': 5,
                'Attribute': no_attribute
            }
            objects.append(new_object)
        # update event object list
        event['Object'] = list(objects)

        # update event defintion
        events[eventkey] = event
    # events are prepared; now return them
    return events


def process_misp_events(helper, config, results, event_list):
    # get parameters for requests
    misp_url_create = config['misp_url'] + '/events/add'

    status = 200
    connection, connection_status = urllib_init_pool(helper, config)
    for eventkey in results:
        helper.log_debug("[AL-PME-D01] payload is {}".format(results[eventkey]))
        if event_list[eventkey] == "0":  # create new event

            if connection:
                response = urllib_request(helper, connection, 'POST', misp_url_create, results[eventkey], config) 
            else:
                response = connection_status

            if '_raw' not in response:
                helper.log_info(
                    "[AL-PME-I02] INFO MISP event is successfully created. url={}".format(misp_url_create)
                )
            else:
                helper.log_error(
                    "[AL-PME-E01] ERROR MISP event creation has failed. "
                    "url={}, response={}"
                    .format(misp_url_create, response)
                )
        else:  # edit existing eventid with Attribute and Object
            misp_url_edit = config['misp_url'] + '/events/edit/' + \
                event_list[eventkey]
            edit_body = {}
            edit_body['Attribute'] = results[eventkey]['Attribute']
            edit_body['Object'] = results[eventkey]['Object']
            if connection:
                response = urllib_request(helper, connection, 'POST', misp_url_edit, edit_body, config)
            else:
                response = connection_status 
            if '_raw' not in response:
                helper.log_info(
                    "[AL-PME-I04] INFO MISP event is successfully edited. url={}".format(misp_url_edit)
                )
            else:
                helper.log_error(
                    "[AL-PME-E02] ERROR MISP event edition has failed. "
                    "url={}, response={}"
                    .format(misp_url_edit, response)
                )
            
    return status


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
