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
'''
{
    "values": "mandatory",
    "id": "mandatory",
    "type": "optional",
    "source": "optional",
    "timestamp": "optional",
    "date": "optional",
    "time": "optional"
}
'''
import os
import sys
import json
import gzip
import csv
import ConfigParser
import time
import requests

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def group_values(r,tslabel,ds):
    # mode byvalue:
    # iterate through each row, cleaning multivalue fields and then
    # adding the values under same timestamp; this builds the dict sightings
    sightings = {}
    for row in r:

        # Splunk makes a bunch of dumb empty multivalue fields - we filter those out here
        row = {key: value for key, value in row.iteritems() if not key.startswith("__mv_")}

        # Get the timestamp as string to group values and remove from row
        if tslabel in row:
            timestamp = str(row.pop(tslabel))
        else:
            timestamp = ds

        # check if building sighting has been initiated
        # if yes simply add attribute entry otherwise collect other metadata
        if timestamp in sightings:
            data = sightings[timestamp]
        else:
            data = []

        # now we take remaining KV pairs on the line to add data to list
        for key, value in row.iteritems():
            if value != "":
                print >> sys.stderr, "DEBUG key %s value %s" % (key, value)
                data.append(str(value))

        sightings[timestamp] = data

    return sightings


def create_alert(config, results):
    print >> sys.stderr, "DEBUG Creating alert with config %s" % json.dumps(config)

    # get the misp_url we need to connect to MISP
    # this can be passed as params of the alert. Defaults to values set in misp.conf
    # get MISP settings stored in misp.conf
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']

    # open misp.conf
    config_file = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'local' + os.sep + 'misp.conf'
    mispconf = ConfigParser.RawConfigParser()
    mispconf.read(config_file)

    # get specific misp url and key if any (from alert configuration)
    misp_url = config.get('misp_url')
    misp_key = config.get('misp_key')

    # If no specific MISP instances defined, get settings from misp.conf
    if misp_url and misp_key:
        misp_url = str(misp_url) + '/sightings/add'
        misp_verifycert = int(config.get('misp_verifycert', "0"))
        if misp_verifycert == 1:
            misp_verifycert = True
        else:
            misp_verifycert = False
    else:
        misp_url = str(mispconf.get('mispsetup', 'misp_url')) + '/sightings/add'
        misp_key = mispconf.get('mispsetup', 'misp_key')
        if mispconf.has_option('mispsetup','misp_verifycert'):
            misp_verifycert = mispconf.getboolean('mispsetup', 'misp_verifycert')
        else:
            misp_verifycert = False

    # Get mode set in alert settings; either byvalue or byuuid
    mode = config.get('mode', 'byvalue')
    # Get type set in alert settings; either 0, 1 or 2
    sighting_type = int(config.get('s_type', '0'))

    # iterate through each row, cleaning multivalue fields and then
    #   mode byvalue: adding the values under same timestamp
    #   mode byuuid:  adding attribute uuid(s) under same timestamp
    # this builds the dict sightings
    # Get field name containing timestamps for sighting - defined in alert

    defaulttimestamp = str(int(time.time()))
    tslabel = config.get('unique', defaulttimestamp)

    if mode == 'byvalue': 
        sightings = group_values(results, tslabel, defaulttimestamp)
    else:
        # Get the timestamp as string to group values and remove from row
        sightings = {}
        for row in results:
            if tslabel in row:
                timestamp = str(row.pop(tslabel))
            else:
                timestamp = defaulttimestamp

            if 'uuid' in row:
                value = row['uuid']
                if value != "":
                    sightings[value] = timestamp

    # set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = misp_key
    headers['Accept'] = 'application/json'

    # iterate in dict events to create events
    for key, data in sightings.items():
        if mode == 'byvalue':
            sighting = json.dumps(dict(
                timestamp=int(key),
                values=data,
                type=sighting_type
            ))
        else:
            sighting = json.dumps(dict(
                timestamp=int(data),
                id=key,
                type=sighting_type
            ))

        # byvalue: sighting contains {"timestamp": timestamp, "values":["value1", "value2,etc. "]}
        # byuuid:  sighting contains {"timestamp": timestamp, "uuid":"uuid_value"}
        r = requests.post(misp_url, headers=headers, data=sighting, verify=misp_verifycert)
        # check if status is anything other than 200; throw an exception if it is
        r.raise_for_status()
        # response is 200 by this point or we would have thrown an exception

if __name__ == "__main__":
    # make sure we have the right number of arguments - more than 1;
    # and first argument is "--execute"
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        # read the payload from stdin as a json string
        payload = json.loads(sys.stdin.read())
        # extract the file path and alert config from the payload
        configuration = payload.get('configuration')
        filepath = payload.get('results_file')

        # test if the results file exists - this should basically never fail
        # unless we are parsing configuration incorrectly
        # example path this variable should hold:
        # '/opt/splunk/var/run/splunk/12938718293123.121/results.csv.gz'
        if os.path.exists(filepath):
            # file exists - try to open it; fail gracefully
            try:
                # open the file with gzip lib, start making alerts
                # can with statements fail gracefully??
                with gzip.open(filepath) as file:
                    # DictReader lets us grab the first row as a header row and
                    # other lines will read as a dict mapping the header to the
                    # value instead of reading the first line with a regular
                    # csv reader and zipping the dict manually later
                    # at least, in theory
                    reader = csv.DictReader(file)
                    # make the alert with predefined function; fail gracefully
                    create_alert(configuration, reader)
                # by this point - all alerts should have been created with all
                # necessary observables attached to each one
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