
# coding=utf-8

#
# Create Events in MISP from results of alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

"""
{
    "values": "mandatory",
    "id": "mandatory",
    "type": "optional",
    "source": "optional",
    "timestamp": "optional",
    "date": "optional",
    "time": "optional"
}
"""

import json
from misp_common import prepare_config
import requests
import time
import splunklib.client as client
import sys
if sys.version_info[0] > 2:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "4.0.1"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


# encoding = utf-8
def prepare_alert(helper, app_name):
    instance = helper.get_param("misp_instance")
    sessionKey = helper.settings['session_key']
    splunkService = client.connect(token=sessionKey)
    storage = splunkService.storage_passwords
    config_args = prepare_config(helper, app_name, instance, storage)
    if config_args is None:
        return None
    alert_args = dict()
    # Get string values from alert form
    alert_args['mode'] = str(helper.get_param("mode"))
    alert_args['type'] = int(helper.get_param("type"))
    alert_args['source'] = str(helper.get_param("source"))
    if not helper.get_param("unique"):
        alert_args['unique'] = "no_timestamp_field"
    else:
        alert_args['unique'] = str(helper.get_param("unique"))
    config_args.update(alert_args)
    return config_args


def group_values(helper, r, tslabel, ds, source, sighting_type):
    # mode byvalue:
    # iterate through each row, cleaning multivalue fields and then
    # adding the values under same timestamp; this builds the dict sightings
    data_collection = dict()
    source_collection = dict()
    for row in r:

        # Splunk makes a bunch of dumb empty multivalue fields
        # - we filter those out here
        row = {key: value for key, value in list(row.items()) if not key.startswith("__mv_")}

        # Get the timestamp as string to group values and remove from row
        timestamp = str(ds)
        if tslabel in row:
            try:
                timestamp = str(int(row.pop(tslabel)))
            except ValueError:
                pass
        if source in row:
            newSource = str(row.pop(source))
            if newSource not in [None, '']:
                # grabs that field's value and assigns it to source
                source = newSource
        source_collection[timestamp] = source
        # check if building sighting has been initiated
        # if yes simply add attribute entry otherwise collect other metadata
        if timestamp in data_collection:
            data = data_collection[timestamp]
        else:
            data = []
        # now we take remaining KV pairs on the line to add data to list
        for key, value in list(row.items()):
            if value not in [None, '']:
                if '\n' in value:  # was a multivalue field
                    values = value.splitlines()
                    for val in values:
                        if val not in [None, ''] and val not in data:
                            data.append(str(val))
                else:
                    if value not in data:
                        data.append(str(value))

        data_collection[timestamp] = data

    sightings = list()
    for ts, data in list(data_collection.items()):
        sighting = dict(
            timestamp=int(ts),
            values=data,
            source=source_collection[ts],
            type=sighting_type
        )
        sightings.append(sighting)
    return sightings


def create_alert(helper, config):
    # get specific misp url and key if any (from alert configuration)
    misp_url = config['misp_url'] + '/sightings/add'
    misp_key = config['misp_key']
    misp_verifycert = config['misp_verifycert']
    proxies = config['proxies']
    client_cert = config['client_cert_full_path']
    # Get mode set in alert settings; either byvalue or byuuid
    mode = config['mode']
    # Get type set in alert settings; either 0, 1 or 2
    sighting_type = config['type']
    # iterate through each row, cleaning multivalue fields and then
    #   mode byvalue: adding the values under same timestamp
    #   mode byuuid:  adding attribute uuid(s) under same timestamp
    # this builds the dict sightings
    # Get field name containing timestamps for sighting - defined in alert
    default_ts = int(time.time())
    tslabel = config['unique']
    source = config['source']
    results = helper.get_events()
    helper.log_info("[AS302] sighting mode is {}".format(mode))
    if mode == 'byvalue':
        sightings = group_values(helper, results, tslabel, default_ts, source, sighting_type)
    else:
        # Get the timestamp as string to group values and remove from row
        sightings = list()
        for row in results:
            if tslabel in row:
                try:
                    timestamp = int(row.pop(tslabel))
                except ValueError:
                    timestamp = default_ts
            else:
                timestamp = default_ts

            if config['source'] in row:
                newSource = str(row.pop(config['source']))
                if newSource not in [None, '']:
                    # grabs that field's value and assigns it to source
                    source = newSource

            if 'uuid' in row:
                value = row['uuid']
                helper.log_info("[AS303] sighting uuid {}".format(value))
                if value not in [None, '']:
                    # keep only first uuid in mv field (see #74)
                    value = value.splitlines()[0]
                    sighting = dict(
                        id=value,
                        source=source,
                        timestamp=timestamp,
                        type=sighting_type
                    )
                    sightings.append(sighting)

    # set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = misp_key
    headers['Accept'] = 'application/json'

    # iterate in dict events to create events
    for sighting in sightings:
        payload = json.dumps(sighting)
        # byvalue: sighting contains
        # {"timestamp": timestamp, "values":["value1", "value2,etc. "]}
        # byuuid:  sighting contains
        # {"timestamp": timestamp, "uuid":"uuid_value"}
        r = requests.post(
            misp_url, headers=headers, data=payload,
            verify=misp_verifycert, cert=client_cert, proxies=proxies)
        # check if status is anything other than 200;
        # throw an exception if it is
        r.raise_for_status()
        # response is 200 by this point or we would have thrown an exception
        if r.status_code in (200, 201, 204):
            helper.log_info(
                "[AL303] INFO MISP event is successfully edited. "
                "url={}, HTTP status={}".format(misp_url, r.status_code)
            )
        else:
            helper.log_error(
                "[AL304] ERROR MISP event edition has failed. "
                "url={}, data={}, HTTP Error={}, content={}"
                .format(misp_url, payload, r.status_code, r.text)
            )

def process_event(helper, *args, **kwargs):
    """
    # IMPORTANT
    # Do not remove the anchor macro:start and macro:end lines.
    # These lines are used to generate sample code. If they are
    # removed, the sample code will not be updated when configurations
    # are updated.

    [sample_code_macro:start]

    # The following example gets and sets the log level
    helper.set_log_level(helper.log_level)

    # The following example gets the alert action parameters
    # and prints them to the log
    title = helper.get_param("title")
    helper.log_info("title={}".format(title))

    description = helper.get_param("description")
    helper.log_info("description={}".format(description))

    unique = helper.get_param("unique")
    helper.log_info("unique={}".format(unique))

    mode = helper.get_param("mode")
    helper.log_info("mode={}".format(mode))

    type = helper.get_param("type")
    helper.log_info("type={}".format(type))

    misp_instance = helper.get_param("misp_instance")
    helper.log_info("misp_instance={}".format(misp_instance))


    # The following example adds two sample events ("hello", "world")
    # and writes them to Splunk
    # NOTE: Call helper.writeevents() only once after all events
    # have been added
    helper.addevent("hello", sourcetype="sample_sourcetype")
    helper.addevent("world", sourcetype="sample_sourcetype")
    helper.writeevents(index="summary", host="localhost", source="localhost")

    # The following example gets the events that trigger the alert
    events = helper.get_events()
    for event in events:
        helper.log_info("event={}".format(event))

    # helper.settings is a dict that includes environment configuration
    # Example usage: helper.settings["server_uri"]
    helper.log_info("server_uri={}".format(helper.settings["server_uri"]))
    [sample_code_macro:end]
    """

    helper.set_log_level(helper.log_level)
    helper.log_info("[AS101] Alert action misp_alert_sighting started.")

    # TODO: Implement your alert action logic here
    misp_app_name = "misp42splunk"
    misp_config = prepare_alert(helper, misp_app_name)
    if misp_config is None:
        helper.log_error("[AS102] FATAL config dict not initialised")
        return 1
    else:
        helper.log_info("[AS103] config dict is ready to use")
        create_alert(helper, misp_config)
    return 0
