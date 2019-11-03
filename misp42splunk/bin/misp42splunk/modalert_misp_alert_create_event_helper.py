#!/usr/bin/env python
#
# Create Events in MISP from results of alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
from __future__ import print_function

import csv
import datetime
import gzip
import json
import os
import requests
import time
from splunk.clilib import cli_common as cli
import splunklib.client as client
from io import open

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.1.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"

#
# most of the code here was based on the following example on splunk custom alert event_list
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample

# encoding = utf-8
def prepare_alert_config(helper):
    config_args = dict()
    # get MISP instance to be used
    misp_instance = helper.get_param("misp_instance")
    stanza_name   = 'misp://' + misp_instance
    helper.log_info("stanza_name={}".format(stanza_name))
    # get MISP instance parameters
    # open local/inputs.conf
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    app_name     = 'misp42splunk'
    inputs_conf_file = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + app_name + os.sep + 'local' + os.sep + 'inputs.conf'
    if os.path.exists(inputs_conf_file):
        inputsConf = cli.readConfFile(inputs_conf_file)
        for name, content in list(inputsConf.items()):
            if stanza_name in name:
                mispconf = content
                helper.log_info(json.dumps(mispconf))
        if not mispconf:
            helper.log_error("local/inputs.conf does not contain settings for stanza: {}".format(stanza_name)) 
    else:
        helper.log_error("local/inputs.conf does not exist. Please configure misp instances first.") 
    # get clear version of misp_key
    # get session key
    sessionKey = helper.settings['session_key']
    splunkService = client.connect(token=sessionKey)
    storage_passwords = splunkService.storage_passwords
    config_args['misp_key'] = None
    for credential in storage_passwords:
        usercreds = {'username':credential.content.get('username'),'password':credential.content.get('clear_password')}
        if misp_instance in credential.content.get('username') and 'misp_key' in credential.content.get('clear_password'):
            misp_instance_key = json.loads(credential.content.get('clear_password'))
            config_args['misp_key'] = str(misp_instance_key['misp_key'])
            helper.log_info('misp_key found for instance  {}'.format(misp_instance))
    if config_args['misp_key'] is None:
        helper.log_error('misp_key NOT found for instance  {}'.format(misp_instance))         

    # get MISP settings stored in inputs.conf
    config_args['misp_url'] = mispconf['misp_url']
    helper.log_info("config_args['misp_url'] {}".format(config_args['misp_url']))
    if int(mispconf['misp_verifycert']) == 1:
        config_args['misp_verifycert'] = True
    else:
        config_args['misp_verifycert'] = False
    helper.log_info("config_args['misp_verifycert'] {}".format(config_args['misp_verifycert']))
    # get client cert parameters
    if int(mispconf['client_use_cert']) == 1:
        config_args['client_cert_full_path'] = mispconf['client_cert_full_path']
    else:
        config_args['client_cert_full_path'] = None
    helper.log_info("config_args['client_cert_full_path'] {}".format(config_args['client_cert_full_path']))
    # get proxy parameters if any
    config_args['proxies'] = dict()
    if int(mispconf['misp_use_proxy']) == 1:
        proxy = helper.get_proxy()
        if proxy:
            proxy_url = '://'
            if proxy['proxy_username'] is not '':
                proxy_url = proxy_url + proxy['proxy_username'] + ':' + proxy['proxy_password'] + '@' 
            proxy_url = proxy_url + proxy['proxy_url'] + ':' + proxy['proxy_port'] + '/'
            config_args['proxies'] = {
                "http":  "http"  + proxy_url,
                "https": "https" + proxy_url
            }
    # Get string values from alert form
    config_args['tlp']= str(helper.get_param("tlp").replace('_',':'))
    config_args['pap']= str(helper.get_param("pap").replace('_',':'))
    if not helper.get_param("eventid"):
        config_args['eventid'] = "0"
    else:
        config_args['eventid'] = str(helper.get_param("eventid"))
    if not helper.get_param("unique"): 
        config_args['eventkey'] = "oneEvent"
    else:
        config_args['eventkey'] = str(helper.get_param("unique"))
    if not helper.get_param("info"):
        config_args['info'] = "notable event"
    else:
        config_args['info'] = str(helper.get_param("info"))
    tags = helper.get_param("tags")
    if tags:
        config_args['tags'] = str(helper.get_param("tags"))
    else:
        config_args['tags'] = None
    # Get numeric values from alert form
    config_args['analysis']     = int(helper.get_param("analysis"))
    config_args['threatlevel']  = int(helper.get_param("threatlevel"))
    config_args['distribution'] = int(helper.get_param("distribution"))
    
    # add filename of the file containing the result of the search
    config_args['filename'] = str(helper.settings['results_file'])

    return config_args


def store_attribute(t, v, to_ids=None, category=None, attribute_tag=None, comment=None):
    Attribute = {}
    Attribute['type'] = t
    Attribute['value'] = v
    if to_ids is not None:
        Attribute['to_ids'] = to_ids
    if category is not None:
        Attribute['category'] = category
    if comment is not None:
        Attribute['comment'] = comment
        # append event tags provided in the row
    if attribute_tag is not None:
        att_tags = []
        att_tag_list = attribute_tag.split(',')
        for atag in att_tag_list:
            if atag not in att_tags:
                new_tag = { 'name': atag }
                att_tags.append(new_tag)
        # update event tag list
        Attribute['Tag'] = att_tags
    return Attribute


def store_object_attribute(ot, t, v, attribute_tag=None):
    try:
        # open object definition.json
        _SPLUNK_PATH = os.environ['SPLUNK_HOME']
        # open misp.conf
        object_definition = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'bin' + os.sep + ot + '_definition.json'
        with open(object_definition) as json_object:
            od = json.load(json_object)
            object_attributes = od['attributes']
            Attribute = {}
            if t in object_attributes:
                Attribute['type'] = object_attributes[t]['misp-attribute']
                Attribute['object_relation'] =  t
                Attribute['value'] = v
        if attribute_tag is not None:
            att_tags = []
            att_tag_list = attribute_tag.split(',')
            for atag in att_tag_list:
                if atag not in att_tags:
                    new_tag = { 'name': atag }
                    att_tags.append(new_tag)
            # update event tag list
            Attribute['Tag'] = att_tags    
        return Attribute
    except IOError as e:
        print("FATAL %s object definition could not be opened/read" % ot)
        exit(3)    


def prepare_misp_events(helper, config, results, event_list):
    # print(config)
    # iterate through each row, cleaning multivalue fields and then adding the attributes under same event key
    # this builds the dict events
    events = {}
    event_baseline = {
        'threat_level_id': config['threatlevel'],
        'analysis': config['analysis'],
        'distribution': config['distribution'],
        'published': False,
        'Attribute': [],
        'Object': []
    }
    # tag the event with TLP level
    tags = [{ 'name': config['tlp']}]
    # Add tags set in alert definition
    if config['tags'] is not None:
        tag_list = config['tags'].split(',')
        for tag in tag_list:
            if tag not in tags:
                new_tag = { 'name': tag }
                tags.append(new_tag)
    event_baseline['Tag'] = tags

    for row in results:
        # Splunk makes a bunch of dumb empty multivalue fields - we filter those out here
        row = {key: value for key, value in list(row.items()) if not key.startswith("__mv_")}

        # Get the specific eventkey if defined in Splunk search. Defaults to alert form value
        eventkey = config['eventkey']
        if eventkey in row:
            eventkey = str(row[eventkey])
        helper.log_info("eventkey is {}".format(eventkey))
        # Get the specific eventid if define in Splunk search. Defaults to alert form value
        # Value == 0: means create new event
        # Value <> 0: edit existing event
        eventid = config['eventid'] # from the alert conf
        if 'eventid' in row:        # from the result row (overwrites other values)
            eventid = str(row.pop('eventid'))
        helper.log_info("eventid is {}".format(eventid))

        # check if building event has been initiated
        # if yes simply add attribute entry otherwise collect other metadata
        # remove fields misp_time and info from row and keep their values if this is a new event
        if eventkey in events:
            event = events[eventkey]
            if 'misp_time' in row:
                row.pop('misp_time')
            if 'misp_info' in row:
                row.pop('misp_info')
        else:
            event_list[eventkey] = eventid
            event = event_baseline.copy()
            if 'misp_time' in row:
                event['date'] = datetime.datetime.fromtimestamp(int(row.pop('misp_time'))).strftime('%Y-%m-%d')
            else:
                event['date'] = datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y-%m-%d')
            if 'misp_info' in row:
                event['info'] = row.pop('misp_info')
            else:
                event['info'] = config['info']
        attributes = list(event['Attribute'])
        objects = list(event['Object'])
        tags = list(event['Tag'])

        # append event tags provided in the row
        if 'misp_tag' in row:
            tag_list = row.pop('misp_tag').split(',')
            for tag in tag_list:
                if tag not in tags:
                    new_tag = { 'name': tag }
                    tags.append(new_tag)

        # update event tag list
        event['Tag'] = list(tags)

        # collect attribute value and build type=value entry
        if 'misp_to_ids' in row:
            if str(row.pop('misp_to_ids')) == 'True':
                to_ids = True
            else:
                to_ids = False
        else:
            to_ids = None
        if 'misp_category' in row:
            category = str(row.pop('misp_category'))
        else:
            category = None
        if 'misp_attribute_tag' in row:
            attribute_tag = str(row.pop('misp_attribute_tag'))
        else:
            attribute_tag = None
        if 'misp_comment' in row:
            comment = str(row.pop('misp_comment'))
        else:
            comment = None

        # now we take KV pairs starting by misp_ to add to event as single attribute(s)
        for key, value in list(row.items()):
            if key.startswith("misp_") and value != "":
                misp_key = str(key).replace('misp_', '').replace('_', '-')
                attributes.append(store_attribute(misp_key, str(value), to_ids=to_ids, category=category, attribute_tag=attribute_tag, comment=comment))

        # update event attribute list
        event['Attribute'] = list(attributes)

        # now we look for attribute belonging to a file email or network object i.e.
        # on the same row, field(s) start(s) with fo_, eo_ or no_
        fo_attribute = []
        eo_attribute = []
        no_attribute = []
        for key, value in list(row.items()):
            if key.startswith("fo_") and value != "":
                fo_key = str(key).replace('fo_', '').replace('_', '-')
                object_attribute = store_object_attribute('file',fo_key, str(value), attribute_tag=attribute_tag)
                if object_attribute:
                    fo_attribute.append(object_attribute)
            if key.startswith("eo_") and value != "":
                eo_key = str(key).replace('eo_', '').replace('_', '-')
                object_attribute = store_object_attribute('email',eo_key, str(value), attribute_tag=attribute_tag)
                if object_attribute:
                    eo_attribute.append(object_attribute)
            if key.startswith("no_") and value != "":
                no_key = str(key).replace('no_', '').replace('_', '-')
                object_attribute = store_object_attribute('domain-ip',no_key, str(value), attribute_tag=attribute_tag)
                if object_attribute:
                    no_attribute.append(object_attribute)

        if fo_attribute:
            new_object = {
                'name': 'file',
                'distribution': 5,
                'Attribute': fo_attribute
            }
            objects.append(new_object)

        if eo_attribute:
            new_object = {
                'name': 'email',
                'distribution': 5,
                'Attribute': eo_attribute
            }
            objects.append(new_object)

        if no_attribute:
            new_object = {
                'name': 'domain-ip',
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

    misp_url_create = config['misp_url'] + '/events/add'
    misp_key = config['misp_key']
    misp_verifycert = config['misp_verifycert']

    # set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = misp_key
    headers['Accept'] = 'application/json'

    # client cert file
    client_cert = config['client_cert_full_path']

    status = 200
    for eventkey in results:
        if event_list[eventkey] == "0": # create new event
            body = json.dumps(results[eventkey])
            helper.log_info("create body has been prepared for eventkey {}".format(eventkey))
            # POST json data to create events
            r = requests.post(misp_url_create, headers=headers, data=body, verify=misp_verifycert, cert=client_cert, proxies=config['proxies'])
            # check if status is anything other than 200; throw an exception if it is
            r.raise_for_status()
            # response is 200 by this point or we would have thrown an exception
            response = r.json()
            helper.log_info("event created")
        else: # edit existing eventid with Attribute and Object
            misp_url_edit = config['misp_url'] + '/events/edit/' + event_list[eventkey]
            edit_body = {}
            edit_body['Attribute'] = results[eventkey]['Attribute']
            edit_body['Object'] = results[eventkey]['Object']
            body = json.dumps(edit_body)
            helper.log_info("edit body has been prepared for eventid {}".format(event_list[eventkey]))
            # POST json data to create events
            r = requests.post(misp_url_edit, headers=headers, data=body, verify=misp_verifycert, cert=client_cert, proxies=config['proxies'])
            # check if status is anything other than 200; throw an exception if it is
            r.raise_for_status()
            # response is 200 by this point or we would have thrown an exception
            response = r.json()
            helper.log_info("event edited")
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

    # The following example gets the alert action parameters and prints them to the log
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
    helper.log_info("Alert action misp_alert_create_event started.")
    
    # TODO: Implement your alert action logic here
    Config = prepare_alert_config(helper)
    helper.log_info("Config dict is ready to use")
    
    filename = Config['filename']
    if os.path.exists(filename):
        # file exists - try to open and if successful add path to configuration
        try:
            # open the file with gzip lib, start making alerts
            # can with statements fail gracefully??
            with gzip.open(filename, 'rt') as file:
                # DictReader lets us grab the first row as a header row and
                # other lines will read as a dict mapping the header
                # to the value instead of reading the first line with a
                # regular csv reader and zipping the dict manually later at
                # least, in theory
                Reader = csv.DictReader(file)
                helper.log_debug("Reader is {}".format(Reader))
                event_list = {}
                Events = prepare_misp_events(helper, Config, Reader, event_list)
                helper.log_info("Events dict is ready to use")
                status = process_misp_events(helper, Config, Events, event_list)
        # something went wrong with opening the results file
        except IOError as e:
            helper.log_error("FATAL Results file exists but could not be opened/read")
            return 2

    return 0
