
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

from misp_common import prepare_config, urllib_init_pool, urllib_request
import time
import splunklib.client as client

__author__ = "Remi Seguy"
__license__ = "LGPLv3"
__version__ = "5.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"


# encoding = utf-8
def prepare_alert(helper, app_name):
    instance = helper.get_param("misp_instance")
    session_key = helper.settings['session_key']
    splunk_service = client.connect(token=session_key)
    storage = splunk_service.storage_passwords

    config_args = prepare_config(helper, app_name, instance, storage, session_key)
    if config_args is None:
        return None

    alert_args = {
        'mode': str(helper.get_param("mode")),
        'type': int(helper.get_param("type")),
        'source': str(helper.get_param("source")),
        'timestamp': str(helper.get_param("timestamp") or "no_timestamp_field")
    }

    config_args.update(alert_args)
    return config_args


def group_values(helper, rows, tslabel, default_ts, source, sighting_type):
    data_collection = dict()
    source_collection = dict()

    def get_timestamp(row):
        try:
            return str(int(row.pop(tslabel, default_ts)))
        except ValueError:
            return str(default_ts)

    def update_source(row, current_source):
        new_source = str(row.pop(source, current_source))
        return new_source if new_source else current_source

    for row in rows:
        row = {key: value for key, value in row.items() if not key.startswith("__mv_")}

        timestamp = get_timestamp(row)
        source_collection[timestamp] = str(row.pop(source, source))
        data = data_collection.get(timestamp, [])
        for key, value in row.items():
            for single in str(value).split("\n"):
                if single.strip() and single != '0' and single not in data:
                    data.append(single)

        data_collection[timestamp] = data

    sightings = [
        {
            'timestamp': int(ts),
            'values': data,
            'source': source_collection[ts],
            'type': sighting_type
        }
        for ts, data in data_collection.items()
    ]

    return sightings


def create_alert(helper, config):
    # get specific misp url and key if any (from alert configuration)
    misp_url = f"{config['misp_url']}/sightings/add"
    mode = config['mode']
    sighting_type = config['type']  # 0, 1, 2
    default_ts = int(time.time())
    results = helper.get_events()
    helper.log_info(f"[AS302] sighting mode is {mode}")

    if mode == 'byvalue':
        sightings = group_values(helper, results, config['timestamp'], default_ts, config['source'], sighting_type)
    else:
        sightings = []
        for row in results:
            if 'misp_attribute_uuid' in row:
                timestamp = int(row.pop(config['timestamp'], default_ts))
                source = str(row.pop(config['source'], config['source']))
                value = row['misp_attribute_uuid']
                helper.log_info(f"[AS303] sighting misp attribute uuid {value}")
                if value.strip() and value != '0':
                    value = value.splitlines()
                    for uuid in list(value):
                        sighting = {
                            'id': uuid,
                            'source': source,
                            'timestamp': timestamp,
                            'type': sighting_type
                        }
                        sightings.append(sighting)

    connection, connection_status = urllib_init_pool(helper, config)
    for sighting in sightings:
        response = urllib_request(helper, connection, 'POST', misp_url, sighting, config) if connection else connection_status
        if '_raw' not in response:
            helper.log_info("[AL303] INFO MISP event is successfully edited.")
        else:
            helper.log_error(f"[AL304] ERROR MISP event edition has failed. url={misp_url}, data={response}")


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

    timestamp = helper.get_param("timestamp")
    helper.log_info("timestamp={}".format(timestamp))

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
