#!/usr/bin/python3
#
# Extract IOC's from MISP
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
import sys, os, json, urllib3, datetime, time, gzip, csv
import pickle
from pymisp import PyMISP

def init(url, key, ssl):
    return PyMISP(url, key, ssl, 'json')

def create_event(m,d,t,a,info,ts):
    result = m.new_event(d,t,a,info,ts)
    return result

def add_attribute(m,e,t,v,c,to_ids):
    # set distribution to 5 so attributes inherit the distribution level from the event
    result = m.add_named_attribute(e,t,v,c,to_ids,distribution=5)
    return result

def get_event(m, e):
    result = m.get_event(e)
    return result['Event']['Attribute']


def store_attribute(t,v,to_ids=False,category=None):
    Attribute = {}
    Attribute['type']     = t
    Attribute['value']    = v
    Attribute['to_ids']   = to_ids
    Attribute['category'] = category
    return Attribute

def create_misp_events(config,results):
    # print(config)
    # iterate through each row, cleaning multivalue fields and then adding the attributes under same event key
    # this builds the dict events
    events = {}
    for row in results:
        # Splunk makes a bunch of dumb empty multivalue fields - we filter those out here 
        row = {key: value for key, value in row.items() if not key.startswith("__mv_")}

        # GEt the specific eventkey if define in Splunk search. Defaults to alert form got above
        eventkey = config['eventkey']
        if eventkey in row:
            eventkey = row.pop(eventkey)

        # check if building event has been initiated
        # if yes simply add attribute entry otherwise collect other metadata
        # remove fields _time and info from row and keep their values if this is a new event
        if eventkey in events:
            event = events[eventkey]
            artifacts = event['attribute']
            if '_time' in row:
                remove = str(row.pop('_time'))
            if 'info' in row:
                remove = row.pop('info')
        else:
            event = {}
            artifacts = []
            if '_time' in row:
                event['timestamp'] = str(row.pop('_time'))
            else:
                event['timestamp'] = str(int(time.time()))
            if 'info' in row:
                event['info'] = row.pop('info')
            else:
                event['info'] = config['info']

        # collect attribute value and build type=value entry
        if 'to_ids' in row:
            if str(row.pop('to_ids')) == 'True':
                to_ids == True
            else:
                to_ids = False
        else:
            to_ids = False
        
        if 'category' in row:
            category = str(row.pop('category'))
        else:
            category = None

        # now we take remaining KV pairs starting by misp_ to add to dict 
        for key, value in row.items():
            if key.startswith("misp_") and value != "":
                misp_key = str(key).replace('misp_','').replace('_','-')
                artifacts.append(store_attribute(misp_key,str(value),to_ids,category))

        event['attribute'] = artifacts
        
        events[eventkey] = event

    # events are prepared; now create them in MISP
    # print(events)
    
    mispsrv  = config['mispsrv']
    mispkey  = config['mispkey']
    sslcheck = config['sslcheck']

    # connect to misp instance using url, authkey and boolean sslcheck
    misp = init(mispsrv, mispkey, sslcheck)

    # extract from config and event the values to create events
    analysis = config['analysis']
    distrib  = config['distribution']
    threat   = config['threatlevel']

    #iteration in events
    eventlist = {}    
    for key, event in events.items():
        date     = datetime.datetime.fromtimestamp(int(event['timestamp'])).strftime('%Y-%m-%d')
        info     = event['info']

        # creqte the event in misp instqnce
        my_event=create_event(misp,distrib,threat,analysis,info,date)

        # tag the event with TLP level
        tlp  = config['tlp']
        # get UUID from new event - required for tag()
        uuid = my_event['Event']['uuid']
        misp.tag(uuid,tlp)

        # add atrributes to event
        # get ID from new event
        eid = int(my_event['Event']['id'])
        # loop for attribute entries
        # please note that distribution will be force to 5 = inherit - if not provided default to your organisation
        for a in event['attribute']:
            updated = add_attribute(misp,eid,a['type'],a['value'],a['category'],a['to_ids'])
        eventlist['eid'] = uuid

    return eventlist

try:
    swap_file = str(sys.argv[1])
    config    = pickle.load(open(swap_file, "rb"))
    filename  = config['filename']
    if os.path.exists(filename):
        # file exists - try to open and if successful add path to configuration
        try:
        # open the file with gzip lib, start making alerts
        # can with statements fail gracefully??
            with gzip.open(filename, 'rt') as file:
            # DictReader lets us grab the first row as a header row and other lines will read as a dict mapping the header to the value
            # instead of reading the first line with a regular csv reader and zipping the dict manually later at least, in theory
                reader = csv.DictReader(file)
                events = create_misp_events(config,reader)

        except IOError as e:
            print("FATAL Results file exists but could not be opened/read")
            exit(2)

except IOError as e:
    print("Error in pymisp_create_event.py %s" % e)
    exit(1)
