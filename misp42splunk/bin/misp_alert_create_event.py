#!/usr/bin/env python
#
# Create Events in MISP from results of alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
# most of the code here was based on the following example on splunk custom alert event_list
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample

import csv
import datetime
import gzip
import json
import os
import requests
import sys
import time
from splunk.clilib import cli_common as cli
import logging

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "2.0.14"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def store_attribute(t, v, to_ids=None, category=None, comment=None):
    Attribute = {}
    Attribute['type'] = t
    Attribute['value'] = v
    if to_ids is not None:
        Attribute['to_ids'] = to_ids
    if category is not None:
        Attribute['category'] = category
    if comment is not None:
        Attribute['comment'] = comment
    return Attribute


def store_object_attribute(ot, t, v):
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
    
        return Attribute
    except IOError as e:
        print("FATAL %s object definition could not be opened/read" % ot)
        exit(3)    


def prepare_misp_events(config, results, event_list):
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
        row = {key: value for key, value in row.items() if not key.startswith("__mv_")}

        # Get the specific eventkey if defined in Splunk search. Defaults to alert form value
        eventkey = config['eventkey']
        if eventkey in row:
            eventkey = str(row[eventkey])
        # Get the specific eventid if define in Splunk search. Defaults to alert form value
        # Value == 0: means create new event
        # Value <> 0: edit existing event
        eventid = config['eventid']
        if 'eventid' in row:
            eventid = str(row.pop('eventid'))
        logging.info("eventid is %s", eventid)

        # check if building event has been initiated
        # if yes simply add attribute entry otherwise collect other metadata
        # remove fields misp_time and info from row and keep their values if this is a new event
        if eventkey in events:
            event = events[eventkey]
            attributes = event['Attribute']
            objects = event['Object']
            tags = event['Tag']
            if 'misp_time' in row:
                row.pop('misp_time')
            if 'misp_info' in row:
                row.pop('misp_info')
        else:
            event_list[eventkey] = eventid
            event = event_baseline
            attributes = event['Attribute']
            objects = event['Object']
            tags = event['Tag']
            if 'misp_time' in row:
                event['date'] = datetime.datetime.fromtimestamp(int(row.pop('misp_time'))).strftime('%Y-%m-%d')
            else:
                event['date'] = datetime.datetime.fromtimestamp(int(time.time())).strftime('%Y-%m-%d')
            if 'misp_info' in row:
                event['info'] = row.pop('misp_info')
            else:
                event['info'] = config['misp_info']

        # append event tags provided in the row
        if 'misp_tag' in row:
            tag_list = row.pop('misp_tag').split(',')
            for tag in tag_list:
                if tag not in tags:
                    new_tag = { 'name': tag }
                    tags.append(new_tag)

        # update event tag list
        event['Tag'] = tags

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
        if 'misp_comment' in row:
            comment = str(row.pop('misp_comment'))
        else:
            comment = None

        # now we take KV pairs starting by misp_ to add to event as single attribute(s)
        for key, value in row.items():
            if key.startswith("misp_") and value != "":
                misp_key = str(key).replace('misp_', '').replace('_', '-')
                attributes.append(store_attribute(misp_key, str(value), to_ids, category, comment))

        # update event attribute list
        event['Attribute'] = attributes

        # now we look for attribute belonging to a file email or network object i.e.
        # on the same row, field(s) start(s) with fo_, eo_ or no_
        fo_attribute = []
        eo_attribute = []
        no_attribute = []
        for key, value in row.items():
            if key.startswith("fo_") and value != "":
                fo_key = str(key).replace('fo_', '').replace('_', '-')
                object_attribute = store_object_attribute('file',fo_key, str(value))
                if object_attribute:
                    fo_attribute.append(object_attribute)
            if key.startswith("eo_") and value != "":
                eo_key = str(key).replace('eo_', '').replace('_', '-')
                object_attribute = store_object_attribute('email',eo_key, str(value))
                if object_attribute:
                    eo_attribute.append(object_attribute)
            if key.startswith("no_") and value != "":
                no_key = str(key).replace('no_', '').replace('_', '-')
                object_attribute = store_object_attribute('domain-ip',no_key, str(value))
                if object_attribute:
                    no_attribute.append(object_attribute)

        if fo_attribute:
            new_object = {
                'name': 'file',
                'Attribute': fo_attribute
            }
            objects.append(new_object)

        if eo_attribute:
            new_object = {
                'name': 'email',
                'Attribute': eo_attribute
            }
            objects.append(new_object)

        if no_attribute:
            new_object = {
                'name': 'domain-ip',
                'Attribute': no_attribute
            }
            objects.append(new_object)
        # update event object list
        event['Object'] = objects

        # update event defintion
        events[eventkey] = event

    # events are prepared; now return them
    return events


def process_misp_events(config, results, event_list):

    misp_url_create = config['misp_url'] + '/events/add'
    misp_key = config['misp_key']
    misp_verifycert = config['misp_verifycert']

    # set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = misp_key
    headers['Accept'] = 'application/json'

    status = 200
    for eventkey in results:
        if event_list[eventkey] == "0": # create new event
            body = json.dumps(results[eventkey])
            logging.info("create body is %s", body)
            # POST json data to create events
            r = requests.post(misp_url_create, headers=headers, data=body, verify=misp_verifycert, proxies=config['proxies'])
            # check if status is anything other than 200; throw an exception if it is
            r.raise_for_status()
            # response is 200 by this point or we would have thrown an exception
            response = r.json()
            logging.info("event created")
            logging.debug("event created %s", json.dumps(response))
        else: # edit existing eventid with Attribute and Object
            misp_url_edit = config['misp_url'] + '/events/edit/' + event_list[eventkey]
            edit_body = {}
            edit_body['Attribute'] = results[eventkey]['Attribute']
            edit_body['Object'] = results[eventkey]['Object']
            body = json.dumps(edit_body)
            logging.info("edit body is %s", body)
            # POST json data to create events
            r = requests.post(misp_url_edit, headers=headers, data=body, verify=misp_verifycert, proxies=config['proxies'])
            # check if status is anything other than 200; throw an exception if it is
            r.raise_for_status()
            # response is 200 by this point or we would have thrown an exception
            response = r.json()
            logging.info("event edited")
            logging.debug("event edited %s", json.dumps(response))
    return status

def prepare_config(config, filename):
    logging.info("Creating alert with config %s", json.dumps(config))
    
    config_args = {}
    # open misp.conf
    mispconf = cli.getConfStanza('misp','mispsetup')
    # get the misp_url we need to connect to MISP
    # this can be passed as params of the alert. Defaults to values set in misp.conf  
    # get specific misp url and key if any (from alert configuration)
    misp_url = config.get('misp_url')
    misp_key = config.get('misp_key')   
    if misp_url and misp_key:
        misp_url = str(misp_url)
        misp_verifycert = int(config.get('misp_verifycert', "0"))
        if misp_verifycert == 1:
            misp_verifycert = True
        else:
            misp_verifycert = False
    else: 
        # get MISP settings stored in misp.conf
        misp_url = str(mispconf.get('misp_url'))
        misp_key = mispconf.get('misp_key')
        if mispconf.get('misp_verifycert') == 1:
            misp_verifycert = True
        else:
            misp_verifycert = False

    # check and complement config
    config_args['misp_url'] = misp_url
    config_args['misp_key'] = misp_key
    config_args['misp_verifycert'] = misp_verifycert   
    # get proxy parameters if any
    http_proxy = mispconf.get('http_proxy', '')
    https_proxy = mispconf.get('https_proxy', '')
    if http_proxy != '' and https_proxy != '':
        config_args['proxies'] = {
            "http": http_proxy,
            "https": https_proxy
        }
    else:
        config_args['proxies'] = {}

    # Get string values from alert form
    config_args['eventid'] = config.get('eventid', "0")
    config_args['eventkey'] = config.get('unique', "oneEvent")
    config_args['info'] = config.get('info', "notable event")
    config_args['tlp'] = config.get('tlp')
    if 'tags' in config:
        config_args['tags'] = config.get('tags')
    else:
        config_args['tags'] = None

    # Get numeric values from alert form
    config_args['analysis']     = int(config.get('analysis'))
    config_args['threatlevel']  = int(config.get('threatlevel'))
    config_args['distribution'] = int(config.get('distribution'))

    # add filename of the file containing the result of the search
    config_args['filename'] = filename
    logging.info("config_args is %s", json.dumps(config_args))

    return config_args


if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)
    # make sure we have the right number of arguments - more than 1; and first argument is "--execute"
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        # read the payload from stdin as a json string
        payload = json.loads(sys.stdin.read())
        # extract the file path and alert config from the payload
        configuration = payload.get('configuration')
        filename = payload.get('results_file')

        # test if the results file exists - this should basically never fail unless we are parsing configuration incorrectly
        # example path this variable should hold: '/opt/splunk/var/run/splunk/12938718293123.121/results.csv.gz'
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
                    logging.debug('Reader is %s', str(Reader))
                    Config = prepare_config(configuration,filename)
                    logging.debug('Config is %s', json.dumps(Config))
                    event_list = {}
                    Events = prepare_misp_events(Config, Reader, event_list)
                    logging.debug('Events contains %s', json.dumps(Events))
                    #print(json.dumps(Events))
                    status = process_misp_events(Config, Events, event_list)

                # by this point - all alerts shosuld have been created with all necessary observables attached to each one
                # we can gracefully exit now
                sys.exit(0)
            # something went wrong with opening the results file
            except IOError as e:
                logging.error("FATAL Results file exists but could not be opened/read")
                sys.exit(3)
        # somehow the results file does not exist
        else:
            logging.error("FATAL Results file does not exist")
            sys.exit(2)
    # somehow we received the wrong number of arguments
    else:
        logging.error("FATAL Unsupported execution mode (expected --execute flag)")
        sys.exit(1)