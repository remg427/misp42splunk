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
    result = m.add_named_attribute(e,t,v,c,to_ids)
    return result

def get_event(m, e):
    result = m.get_event(e)
    return result['Event']['Attribute']

try:
    config = eval(sys.argv[1])
    event  = eval(sys.argv[2])

    mispsrv  = config['mispsrv']
    mispkey  = config['mispkey']
    sslcheck = config['sslcheck']

    misp = init(mispsrv, mispkey, sslcheck)

    analysis = config['analysis']
    distrib  = config['distribution']
    threat   = config['threatlevel']
    date     = datetime.datetime.fromtimestamp(int(event['timestamp'])).strftime('%Y-%m-%d')
    info     = event['info']

    my_event=create_event(misp,distrib,threat,analysis,info,date)
    eid= my_event['Event']['id']
    for a in event['attribute']:
        updated = add_attribute(misp,eid,a['type'],a['value'],a['category'],a['to_ids'])

    tlp      = config['tlp']

except:
    print("Error in pymisp_create_event.py")
    exit(1)


