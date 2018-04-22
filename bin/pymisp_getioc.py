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
import pickle
import json
import urllib3
from pymisp import PyMISP


def init(url, key, ssl):
    return PyMISP(url, key, ssl, 'json')

def transpose_attributes(d, onlyids, getuuid, getorg, acategory=None, atype=None):
#Search parameters: boolean and filter
# onlyids: boolean
# getuuid: boolean
# getorg: boolean
# category: string
# type: string
    fields = ['event_id','timestamp', 'type', 'category', 'to_ids', 'value']
    if atype != None:
        typelist = atype.split(",")
    else:
        typelist = []
        for a in d:
            if a['type'] not in typelist:
                typelist.append(a['type'])

    if acategory != None:
        selected_categories = acategory.split(",")
    else:
        selected_categories = []

    transpose = []
   
    for a in d:
        r = {}
        # Do not process deleted attributes
        if a['deleted'] == False:
            # Filters
            # If specified, only display attributes with the to-ids flag set to True
            if onlyids == True and a['to_ids'] == False:
                continue
            # If specified, only display attributes from this category
            if acategory != None and a['category'] not in selected_categories:
                continue
            # If specified, only display attributes of one of listed types
            if atype != None and a['type'] not in typelist:
                continue
            # copy minimum set of fields
            for f in fields:
                r[f] = a[f]

            # if specified copy _attribute_ uuid
            if getuuid == True:
                r['uuid'] = a['uuid']
            # if specified copy _event_ ORG
            if getorg == True:
                r['orgc'] = a['orgc']
            
            #finally add columns for each type in data set                
            for t in typelist:
                if a['type'] == t:
                    r[t] = a['value']
                else:
                    r[t] = ''
            transpose.append(r)

    return transpose

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
    swap_file = sys.argv[1]
    config = pickle.load(open(swap_file, "rb"))
    if 'mispsrv' in config:
        mispsrv = config['mispsrv']
    if 'mispkey' in config:
        mispkey = config['mispkey']
    if 'sslcheck' in config:
        sslcheck = config['sslcheck']

    misp = init(mispsrv, mispkey, sslcheck)
    
    if 'eventid' in config:
        extract = get_event(misp, config['eventid'])
        result  = transpose_attributes(extract,config['onlyids'],config['getuuid'],config['getorg'],config['category'],config['type'])
        pickle.dump(result, open(swap_file, "wb"), protocol=2)
    elif 'last'  in config:
        extract = get_last(misp, config['last'])
        result  = transpose_attributes(extract,config['onlyids'],config['getuuid'],config['getorg'],config['category'],config['type'])
        pickle.dump(result, open(swap_file, "wb"), protocol=2)
    else:
        print("Error in pymisp_getioc.py - neither eventid nor last are defined")
        exit(1)
#    exit(0)
    
except:
    print("Error in pymisp_getioc.py")
    exit(1)


