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

def set_sighting(m,s):
    return m.set_sightings(s)

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

    # byvalue: sighting contains {"timestamp": timestamp, "values":["value1", "value2,etc. "]}
    if mode == 'byvalue':
        set_sighting(misp,sighting)
    # byuuid: sighting contains {"timestamp": timestamp, "values":["uuid"]}
    else:
        uuids = sighting['values']
        for uuid in uuids:
            out = sighting_uuid(misp,uuid)

except:
    print("Error in pymisp_sighting.py")
    exit(1)
