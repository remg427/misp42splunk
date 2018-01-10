#!/usr/bin/python3
#
# Extract IOC's from MISP
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
import sys
import os
import json
import urllib3
from pymisp import PyMISP


def init(url, key, ssl):
    return PyMISP(url, key, ssl, 'json')

def get_event(m, e):
    data = []
    result = m.get_event(e)
    for a in result['Event']['Attribute']:
        a['orgc'] = result['Event']['Orgc']['name']
        data.append(a)
    return data

def get_last(m, l):
    result = m.download_last(l)
    data = []
    for r in result['response']:
        for a in r['Event']['Attribute']:
            a['orgc'] = r['Event']['Orgc']['name']
            data.append(a)
    return data

try:
    config = eval(sys.argv[1])

    if 'mispsrv' in config:
        mispsrv = config['mispsrv']
    if 'mispkey' in config:
        mispkey = config['mispkey']
    if 'sslcheck' in config:
        sslcheck = config['sslcheck']

    misp = init(mispsrv, mispkey, sslcheck)

    if 'eventid' in config:
        print(str(get_event(misp, config['eventid'])))
    elif 'last' in config:
        print(str(get_last(misp, config['last'])))
    else:
        print("Error in pymisp_getioc.py - eventid nor last are defined")
        exit(1)
#    exit(0)
    
except:
    print("Error in pymisp_getioc.py")
    exit(1)


