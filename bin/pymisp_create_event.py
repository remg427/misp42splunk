#!/usr/bin/python3
#
# Extract IOC's from MISP
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
import sys
import os
import json
import urllib3
import datetime
from pymisp import PyMISP, MISPEvent

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

try:
    config  = eval(sys.argv[1])
    event   = eval(sys.argv[2])

    mispsrv  = config['mispsrv']
    mispkey  = config['mispkey']
    sslcheck = config['sslcheck']

    # connect to misp instance using url, authkey and boolean sslcheck
    misp = init(mispsrv, mispkey, sslcheck)

    # extract from config and event the values to create events
    analysis = config['analysis']
    distrib  = config['distribution']
    threat   = config['threatlevel']
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

except:
    print("Error in test_pycreate.py")
    exit(1)
