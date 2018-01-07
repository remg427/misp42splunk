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
    dict = eval(sys.argv[1])
except:
    pass

mispsrv = dict['mispsrv']
mispkey = dict['mispkey']
sslcheck = dict['sslcheck']

try:
    misp = init(mispsrv, mispkey, False)
except:
    exit(1)

if 'eventid' in dict:
    print(str(get_event(misp, dict['eventid'])))
elif 'last' in dict:
    print(str(get_last(misp, dict['last'])))
else:
    exit(1)

exit(0)