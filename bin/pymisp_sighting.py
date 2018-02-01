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

def search_uuid(m,v):
    kwargs = {}
    kwargs['values'] = v
    result = m.search('attributes', **kwargs)
    attributes = result['response']['Attribute']
    uuids = []
    for result in attributes:
        uuids.append(result['uuid'])
#    print(json.dumps(uuids, indent=2, separators=(',', ': ') ))
    return uuids

def sighting_uuid(m,uuid):
    return m.sighting_per_uuid(uuid)

try:
    config   = eval(sys.argv[1])
    sighting = eval(sys.argv[2])

    mispsrv  = config['mispsrv']
    mispkey  = config['mispkey']
    sslcheck = config['sslcheck']
    mode     = config['mode']

    # connect to misp instance using url, authkey and boolean sslcheck
    misp = init(mispsrv, mispkey, sslcheck)
#    print(misp)

    timestamp = sighting['timestamp']
    values    = sighting['values']
    
    if mode == 'byvalue':
        for value in values:
    #        print(value)
            uuids = search_uuid(misp, value)
    else:
        uuids = values
    
    for uuid in uuids:
#        print(uuid)
        out = sighting_uuid(misp,uuid)
#        print(out)

except:
    print("Error in pymisp_sighting.py")
    exit(1)
