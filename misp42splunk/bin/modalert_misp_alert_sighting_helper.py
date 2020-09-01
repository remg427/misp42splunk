
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

import csv
import gzip
import json
import os
import requests
import time
from splunk.clilib import cli_common as cli
import splunklib.client as client

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "3.2.2"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


# encoding = utf-8
def prepare_alert_config(helper):
    config_args = dict()
    # get MISP instance to be used
    misp_instance = helper.get_param("misp_instance")
    stanza_name = 'misp://' + misp_instance
    helper.log_info("stanza_name={}".format(stanza_name))
    # get MISP instance parameters
    # open local/inputs.conf
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    app_name = 'misp42splunk'
    inputs_conf_file = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name, 'local', 'inputs.conf')
    if os.path.exists(inputs_conf_file):
        inputsConf = cli.readConfFile(inputs_conf_file)
        for name, content in list(inputsConf.items()):
            if stanza_name in name:
                mispconf = content
                helper.log_info(json.dumps(mispconf))
        if not mispconf:
            helper.log_error(
                "local/inputs.conf does not contain settings for stanza: {}"
                .format(stanza_name))
    else:
        helper.log_error(
            "local/inputs.conf does not exist. \
Please configure misp instances first.")
    # get clear version of misp_key
    # get session key
    sessionKey = helper.settings['session_key']
    splunkService = client.connect(token=sessionKey)
    storage_passwords = splunkService.storage_passwords
    config_args['misp_key'] = None
    for credential in storage_passwords:
        # usercreds = {'username':credential.content.get('username'),
        # 'password':credential.content.get('clear_password')}
        if misp_instance in credential.content.get('username') and \
                'misp_key' in credential.content.get('clear_password'):
            misp_instance_key = json.loads(
                credential.content.get('clear_password'))
            config_args['misp_key'] = str(misp_instance_key['misp_key'])
            helper.log_info('misp_key found for instance \
                {}'.format(misp_instance))
    if config_args['misp_key'] is None:
        helper.log_error('misp_key NOT found for instance \
            {}'.format(misp_instance))

    # get MISP settings stored in inputs.conf
    misp_url = mispconf['misp_url']
    if misp_url.startswith('https://'):
        config_args['misp_url'] = misp_url
        helper.log_info(
            "config_args['misp_url'] {}".format(config_args['misp_url']))
    else:
        helper.log_error(
            "misp_url must starts with HTTPS. Please set a valid misp_url")
        exit(1)
    if int(mispconf['misp_verifycert']) == 1:
        config_args['misp_verifycert'] = True
    else:
        config_args['misp_verifycert'] = False
    helper.log_info(
        "config_args['misp_verifycert'] {}"
        .format(config_args['misp_verifycert']))
    # get client cert parameters
    if int(mispconf['client_use_cert']) == 1:
        config_args['client_cert_full_path'] = mispconf['client_cert_full_path']
    else:
        config_args['client_cert_full_path'] = None
    helper.log_info(
        "config_args['client_cert_full_path'] {}"
        .format(config_args['client_cert_full_path']))
    # get proxy parameters if any
    config_args['proxies'] = dict()
    if int(mispconf['misp_use_proxy']) == 1:
        proxy = helper.get_proxy()
        if proxy:
            proxy_url = '://'
            if 'proxy_username' in proxy:
                if proxy['proxy_username'] not in [None, '']:
                    proxy_url = proxy_url + proxy['proxy_username'] + \
                        ':' + proxy['proxy_password'] + '@'
            proxy_url = proxy_url + proxy['proxy_url'] + \
                ':' + proxy['proxy_port'] + '/'
            config_args['proxies'] = {
                "http": "http" + proxy_url,
                "https": "https" + proxy_url
            }

    # Get string values from alert form
    config_args['mode'] = str(helper.get_param("mode"))
    config_args['type'] = int(helper.get_param("type"))
    config_args['source'] = str(helper.get_param("source"))
    if not helper.get_param("unique"):
        config_args['unique'] = "no_timestamp_field"
    else:
        config_args['unique'] = str(helper.get_param("unique"))

    # add filename of the file containing the result of the search
    config_args['filename'] = str(helper.settings['results_file'])

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


def create_alert(helper, config, results):
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
                if value not in [None, '']:
                    # keep only first uuid in mv field (see #74)
                    value = value.splitlines()[0]
                    sighting = dict(
                        id=value,
                        source=source,
                        timestamp=timestamp,
                        type=sighting_type
                    )
                    sightings.append(sightings)

    # set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = misp_key
    headers['Accept'] = 'application/json'

    # iterate in dict events to create events
    for sighting in list(sightings.items()):
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
    config = prepare_alert_config(helper)
    helper.log_info("[AS102] config dict is ready to use")

    filename = config['filename']
    if os.path.exists(filename):
        # file exists - try to open and if successful add path to configuration
        try:
            # open the file with gzip lib, start making alerts
            # can with statements fail gracefully??
            fh = gzip.open(filename, "rt")
        except ValueError:
            # Workaround for Python 2.7 under Windows
            fh = gzip.open(filename, "r")

        if fh is not None:
            # DictReader lets us grab the first row as a header row and
            # other lines will read as a dict mapping the header
            # to the value instead of reading the first line with a
            # regular csv reader and zipping the dict manually later at
            # least, in theory
            reader = csv.DictReader(fh)
            create_alert(helper, config, reader)
        # something went wrong with opening the results file
        else:
            helper.log_error(
                "[AS102] FATAL Results file exists but could not be opened or read")
            return 2

    return 0
