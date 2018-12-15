#!/usr/bin/env python
#
# Create Events in MISP from results of alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
# most of the code here was based on the following example on splunk custom alert actions
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample

import ConfigParser
import csv
import datetime
import gzip
import json
import os
import requests
import sys
import time

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def store_attribute(t, v, to_ids=False, category=None):
    Attribute = {}
    Attribute['type'] = t
    Attribute['value'] = v
    Attribute['to_ids'] = to_ids
    Attribute['category'] = category
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


def prepare_misp_events(config, results):
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
        'Object': [],

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

        # GEt the specific eventkey if define in Splunk search. Defaults to alert form got above
        eventkey = config['eventkey']
        if eventkey in row:
            eventkey = row.pop(eventkey)

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
            to_ids = False

        if 'misp_category' in row:
            category = str(row.pop('misp_category'))
        else:
            category = None

        # now we take KV pairs starting by misp_ to add to event as single attribute(s)
        for key, value in row.items():
            if key.startswith("misp_") and value != "":
                misp_key = str(key).replace('misp_', '').replace('_', '-')
                attributes.append(store_attribute(misp_key, str(value), to_ids, category))

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


def create_misp_events(config, results):

    #create them in MISP
    # print(events)

    misp_url = config['misp_url'] + '/events/add'
    misp_key = config['misp_key']
    misp_verifycert = config['misp_verifycert']

    # set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = misp_key
    headers['Accept'] = 'application/json'

    status = 200
    for eventkey in results:
        body = json.dumps(results[eventkey])
        # POST json data to create events
        r = requests.post(misp_url, headers=headers, data=body, verify=misp_verifycert)
        # check if status is anything other than 200; throw an exception if it is
        r.raise_for_status()
        # response is 200 by this point or we would have thrown an exception
        response = r.json()
        # print(json.dumps(response))

    return status

def prepare_config(config, filename):
    print >> sys.stderr, "DEBUG Creating alert with config %s" % json.dumps(config)

    # get the misp_url we need to connect to MISP
    # this can be passed as params of the alert. Defaults to values set in misp.conf
    # get MISP settings stored in misp.conf
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    # open misp.conf
    config_file = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'local' + os.sep + 'misp.conf'
    mispconf = ConfigParser.RawConfigParser()
    mispconf.read(config_file)

    # check and complement config
    config_args = {}

    # MISP instance parameters
    misp_url = config.get('misp_url')
    misp_key = config.get('misp_key')

    # If no specific MISP instances defined, get settings from misp.conf
    if misp_url and misp_key:
        config_args['misp_url'] = misp_url
        config_args['misp_key'] = misp_key
        misp_verifycert = int(config.get('misp_verifycert', "0"))
        if misp_verifycert == 1:
            config_args['misp_verifycert'] = True
        else:
            config_args['misp_verifycert'] = False
    else:
        config_args['misp_url'] = mispconf.get('mispsetup', 'misp_url')
        config_args['misp_key'] = mispconf.get('mispsetup', 'misp_key')
        if mispconf.has_option('mispsetup','misp_verifycert'):
            config_args['misp_verifycert'] = mispconf.getboolean('mispsetup', 'misp_verifycert')
        else:
            config_args['misp_verifycert'] = False

    # Get string values from alert form
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

    return config_args


if __name__ == "__main__":
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
                    Config = prepare_config(configuration,filename)

                    Events = prepare_misp_events(Config, Reader)
                    #print(json.dumps(Events))
                    status = create_misp_events(Config, Events)

                # by this point - all alerts should have been created with all necessary observables attached to each one
                # we can gracefully exit now
                sys.exit(0)
            # something went wrong with opening the results file
            except IOError as e:
                print >> sys.stderr, "FATAL Results file exists but could not be opened/read"
                sys.exit(3)
        # somehow the results file does not exist
        else:
            print >> sys.stderr, "FATAL Results file does not exist"
            sys.exit(2)
    # somehow we received the wrong number of arguments
    else:
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)