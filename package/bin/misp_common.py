# coding=utf-8
import json
import os
import re
from splunk.clilib import cli_common as cli
import splunklib
from io import open
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

__license__ = "LGPLv3"
__version__ = "5.0.0"
__maintainer__ = "Remi Seguy"
__email__ = "remg427@gmail.com"

# set up logger suitable for splunkd consumption


def logging_level(app_name):
    """
    This function sets logger to the defined level in
    misp42splunk app and writes logs to a dedicated file
    """
    # retrieve log level
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    settings_file = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name,
        'local', app_name + '_settings.conf'
    )
    run_level = 'ERROR'
    if os.path.exists(settings_file):
        app_settings = cli.readConfFile(settings_file)
        for name, content in list(app_settings.items()):
            if 'logging' in name:
                if 'loglevel' in content:
                    set_level = content['loglevel']
                    if set_level in ['DEBUG', 'INFO', 'WARNING',
                                     'ERROR', 'CRITICAL']:
                        run_level = set_level
    return run_level


def prepare_config(helper, app_name, misp_instance,
                   storage_passwords, session_key=None):
    config_args = dict(
        misp_key=None,
        misp_url=None,
        proxy_url=None,
        misp_verifycert=False,
        client_cert_full_path=None,
        prefix='misp_',
        connection_timeout=3,
        read_timeout=200
    )
    # get settings for MISP instance
    if session_key is None:
        response = helper.service.get('misp42splunk_instances')
    else:
        service = splunklib.client.connect(token=session_key)
        response = service.get('misp42splunk_instances')
    helper.log_debug("[MC-PC-D01] response.status={}".format(response.status))
    if response.status == 200:
        data_body = splunklib.data.load(response.body.read())
    else:
        helper.log_error(
            "[MC-PC-E01] Unexpected status received {}".format(response.status))
        raise Exception(
            "[MC-PC-E01] Unexpected status received %s", str(response.status))
        return None

    foundStanza = False
    instance_count = int(data_body['feed']['totalResults'])
    helper.log_debug("[MC-PC-D02] instance_count={}".format(instance_count))
    if instance_count == 0:  # No misp instance configured
        helper.log_error("[MC-PC-E02] no misp instance configured")
        raise Exception("[MC-PC-E02] no misp instance configured. Please configure an entry for %s", str(misp_instance))
        return None
    elif instance_count == 1:  # Single misp instance configured
        instance = data_body['feed']['entry']
        helper.log_debug("[MC-PC-D03] single instance={}".format(instance))
        if misp_instance == str(instance['title']):
            app_config = instance['content']
            foundStanza = True
    else:  # Multiple misp instances configured
        misp_instances = data_body['feed']['entry']
        for instance in list(misp_instances):
            helper.log_debug("[MC-PC-D04] instance item={}".format(instance))
            if misp_instance == str(instance['title']):
                app_config = instance['content']
                foundStanza = True

    if not foundStanza:
        raise Exception("[MC-PC-E03] no misp_instance with specified name found: %s ", str(misp_instance))
        return None

    # save MISP settings stored in app_config into config_arg
    misp_url = str(app_config.get('misp_url', '')).rstrip('/')
    if misp_url.startswith('https://'):
        config_args['misp_url'] = misp_url
        config_args['host'] = config_args['misp_url'].replace('https://', '')
    else:
        raise Exception("[MC-PC-E04] misp_url must start with https://. Please set a valid misp_url")
        return None

    p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
    m = re.search(p, config_args['misp_url'])
    config_args['host_header'] = m.group('host')  # 'www.abc.com'

    if int(app_config.get('misp_verifycert', '0')) == 1:
        config_args['misp_verifycert'] = True

    misp_ca_full_path = app_config.get('misp_ca_full_path', None)
    if misp_ca_full_path is not None:
        config_args['misp_ca_cert'] = misp_ca_full_path

    # get client cert parameters
    if int(app_config.get('client_use_cert', '0')) == 1:
        config_args['client_cert_full_path'] = app_config.get('client_cert_full_path', 'no_path')

    # test if client certificate file is readable
    if config_args['client_cert_full_path'] is not None:
        try:
            # open client_cert_full_path if exists and log.
            with open(config_args['client_cert_full_path'], 'rb'):
                helper.log_info(
                    "client_cert_full_path file at {} was successfully opened".format(config_args['client_cert_full_path']))
        except IOError:  # file client_cert_full_path  not readable
            helper.log_error(
                "[MC-PC-E05] client_cert_full_path file at {} not readable".format(config_args['client_cert_full_path'])
            )
            raise Exception(
                "[MC-PC-E05] client_cert_full_path file at {} not readable".format(config_args['client_cert_full_path'])
            )
            return None

    # get field prefix - can be overwritten
    config_args['prefix'] = app_config.get('prefix', 'misp_')
    config_args['connection_timeout'] = int(app_config.get('connection_timeout', 3))
    config_args['read_timeout'] = int(app_config.get('read_timeout', 200))

    # get clear version of misp_key and proxy password
    proxy_clear_password = None
    # avoid picking wrong key if stanza is a substring of another stanza
    misp_instance_index = misp_instance + "``splunk_cred_sep``"
    for credential in storage_passwords:
        cred_app_name = credential.access.get('app')
        if (app_name in cred_app_name) and (cred_app_name is not None):
            username = credential.content.get('username')
            if misp_instance_index in username:
                clear_credentials = credential.content.get('clear_password')
                if 'misp_key' in clear_credentials:
                    misp_instance_key = json.loads(clear_credentials)
                    config_args['misp_key'] = str(misp_instance_key['misp_key'])
            elif 'proxy' in username:
                clear_credentials = credential.content.get('clear_password')
                if 'proxy_password' in clear_credentials:
                    proxy_creds = json.loads(clear_credentials)
                    proxy_clear_password = str(proxy_creds['proxy_password'])

    if config_args['misp_key'] is None:
        raise Exception("[MC205] misp_key NOT found for instance {}".format(misp_instance))
        return None

    # get proxy parameters if any
    if int(app_config.get('misp_use_proxy', '0')) == 1:
        proxy = None
        settings_file = os.path.join(
            os.environ['SPLUNK_HOME'], 'etc', 'apps', app_name,
            'local', app_name + '_settings.conf'
        )
        if os.path.exists(settings_file):
            app_settings = cli.readConfFile(settings_file)
            for name, content in list(app_settings.items()):
                if 'proxy' in name:
                    proxy = content
        if proxy:
            config_args['proxy_url'] = 'http://' + proxy['proxy_hostname'] + \
                ':' + proxy['proxy_port'] + '/'
            if 'proxy_username' in proxy \
               and proxy_clear_password is not None:
                if proxy['proxy_username'] not in ['', None]:
                    config_args['proxy_username'] = proxy['proxy_username']
                    config_args['proxy_password'] = proxy_clear_password

    return config_args


def make_list(helper, field):

    temp_v = list()
    temp_v.append(field)

    return temp_v


def splunk_timestamp(input_ts):
    if isinstance(input_ts, list):
        output_ts = int(min(input_ts))
    elif isinstance(input_ts, str):
        output_ts = int(input_ts)
    elif not isinstance(input_ts, int):
        output_ts = int(time.time())
    else:
        output_ts = input_ts
    return output_ts 


def normalise_data(key, value):
    normalised_data = list()
    if isinstance(value, str) or isinstance(value, int) or isinstance(value, float):
        normalised_data.append((key, value))
    if isinstance(value, list):
        for item in value:
            normalised_data.extend(normalise_data(key, item))
    if isinstance(value, dict):
        for k,v in value.items():
            normalised_data.extend(normalise_data(k,v))
    return normalised_data 


def generate_record(data, time=time.time(), generator=None):
    encoder = json.JSONEncoder(ensure_ascii=False, separators=(',', ':'))

    data_dict = dict()
    record = normalise_data('none', data)
    for key, val in record:
        val = str(val)
        key = str(key)
        if key in data_dict:
            if isinstance(data_dict[key], list):
                data_dict[key].append(val)
            else:
                data_dict[key] = [data_dict[key], val]
        else:
            data_dict[key] = val

    data_dict['_time'] = time
    data_dict['_raw'] = encoder.encode(data)

    if generator:
        return generator.gen_record(**data_dict)
    return data_dict


def misp_url_request(url_connection, method, url, body, headers, connection_timeout=3, read_timeout=200):

    if method == "GET":
        r = url_connection.request('GET',
                                   url,
                                   headers=headers,
                                   fields=body,
                                   timeout=urllib3.Timeout(connect=connection_timeout, read=read_timeout)
                                   )
    elif method == 'POST':
        encoded_body = json.dumps(body).encode('utf-8')
        r = url_connection.request('POST',
                                   url,
                                   headers=headers,
                                   body=encoded_body,
                                   timeout=urllib3.Timeout(connect=connection_timeout, read=read_timeout)
                                   )
    elif method == "DELETE":
        encoded_body = json.dumps(body).encode('utf-8')
        r = url_connection.request('DELETE',
                                   url,
                                   headers=headers,
                                   body=encoded_body,
                                   timeout=urllib3.Timeout(connect=connection_timeout, read=read_timeout)
                                   )
    elif method == "PUT":
        encoded_body = json.dumps(body).encode('utf-8')
        r = url_connection.request('PUT',
                                   url,
                                   headers=headers,
                                   body=encoded_body,
                                   timeout=urllib3.Timeout(connect=connection_timeout, read=read_timeout)
                                   )
    else:
        raise Exception(
            "Sorry, no valid method provided (GET/POST/PUT/DELETE)."
            "it was {}.".format(method)
        )
    return r


def urllib_init_pool(helper, config):

    if config['misp_verifycert'] is True:
        kwargs = {"cert_reqs": "CERT_REQUIRED"}
    else:
        kwargs = {"cert_reqs": "CERT_NONE"}

    if config.get('misp_ca_cert', None) is not None:
        kwargs['ca_certs'] = config['misp_ca_cert']
    if config['client_cert_full_path'] is not None:
        kwargs['cert_file'] = config['client_cert_full_path']
    status = None
    if config['proxy_url'] not in [None, '']:
        try:
            if 'proxy_username' in config:
                default_headers = urllib3.make_headers(proxy_basic_auth=config['proxy_username'] + ":" + config['proxy_password'])
                connection = urllib3.ProxyManager(config['proxy_url'], proxy_headers=default_headers, retries=False, **kwargs)
            else:
                connection = urllib3.ProxyManager(config['proxy_url'], retries=False, **kwargs)

            status = {'_time': time.time(),
                      '_raw': "[MC401] DEBUG ProxyManager success verify={} proxy={}".format(
                      config['misp_verifycert'], config['proxy_url'])
                      }

        except Exception as e:  # failed to execute request
            status = {'_time': time.time(),
                      '_raw': "[MC401] DEBUG ProxyManager failed error={} verify={} proxy={}".format(
                      e, config['misp_verifycert'], config['proxy_url'])
                      }
    else:
        try:
            connection = urllib3.PoolManager(retries=False, **kwargs)

            status = {'_time': time.time(),
                      '_raw': "[MC402] DEBUG PoolManager success verify={}".format(
                      config['misp_verifycert'])
                      }

        except Exception as e:  # failed to execute request
            status = {'_time': time.time(),
                      '_raw': "[MC402] DEBUG PoolManager error={} verify={}".format(
                      e, config['misp_verifycert'])
                      }

    return connection, status


def urllib_request(helper, url_connection, method, misp_url, body, config):
    # set proper headers
    headers = {'Content-type': 'application/json'}
    headers['Authorization'] = config['misp_key']
    headers['Accept'] = 'application/json'
    headers['host'] = config['host_header']
    connection_timeout = config.get('connection_timeout', 3)
    read_timeout = config.get('read_timeout', 200)
    try:

        r = misp_url_request(url_connection, method, misp_url, body, headers, connection_timeout, read_timeout)

        if r.status in (200, 201, 204):
            helper.log_info(
                "[MC501] INFO {} request is successful. url={}, HTTP status={}".format(
                    method, misp_url, r.status)
            )
            data = json.loads(r.data.decode('utf-8'))  # return response from MISP (with proxy)
        else:
            helper.log_error(
                "[MC502] ERROR {} request failed. url={}, HTTP status={}".format(
                    method, misp_url, r.status)
            )
            data = {'_time': time.time(),
                    '_raw': json.loads("[MC502] ERROR {} request failed. url={}, HTTP status={}".format(
                        method, misp_url, r.status))
                    }
    except Exception as e:  # failed to execute request
        data = {'_time': time.time(),
                '_raw': "[MC503] DEBUG urlib3 {} request failed error={} url={} body={}".format(
                method, e, misp_url, body)
                }

    return data


def get_attributes(helper, connection, config, body_dict):
    response = list()
    response_count = 0

    body_dict['includeSightings'] = config['include_sightings']
    if config['page'] == 0 and config['limit'] != 0:
        request_loop = True
        body_dict['limit'] = config['limit']
        body_dict['page'] = 1
        while request_loop:
            iter_response = urllib_request(
                helper,
                connection,
                'POST',
                config['misp_url'],
                body_dict,
                config)
            if 'response' in iter_response:
                if 'Attribute' in iter_response['response']:
                    rlength = len(
                        iter_response['response']['Attribute'])
                    if rlength != 0:
                        for attribute in iter_response['response']['Attribute']: 
                            response.append(dict(attribute))
                        helper.log_debug(
                            '[MC-601] request on page {} returned {} attribute(s); querying next page'
                            .format(body_dict['page'], rlength))
                        body_dict['page'] = body_dict['page'] + 1
                        response_count += rlength
                    else:
                        helper.log_debug(
                            '[MC-601] request on page {} returned {} attribute'
                            .format(body_dict['page'], rlength))
                        # last page is reached
                        request_loop = False
                else:
                    request_loop = False
            else:
                request_loop = False
    else:
        body_dict['limit'] = config['limit']
        body_dict['page'] = config['page']
        iter_response = urllib_request(
            helper,
            connection,
            'POST',
            config['misp_url'],
            body_dict,
            config)
        if 'response' in iter_response:
            if 'Attribute' in iter_response['response']:
                for attribute in iter_response['response']['Attribute']: 
                    response.append(dict(attribute))
                response_count = len(iter_response['response']['Attribute'])

    helper.log_info(f'[MC-602] response contains {response_count} records')
    return response


def map_sighting_table(helper, sightings, config):
    """
    { [-]
       Organisation: { [-]
         id: 1
         name: MIRESEC
         uuid: 305d4e1e-80d2-4592-a1d7-b9cec29bb626
       }
       attribute_id: 17886
       attribute_uuid: 669748aa-e70c-4b48-892e-4b2a82a233fa
       date_sighting: 1734503055
       event_id: 57
       id: 13
       org_id: 1
       source:
       type: 0
       uuid: 3f0d52f8-ed19-4284-8455-a2afe6526b29
     } 
    """
    prefix = config.get('prefix', "misp_")
    sighting_metric_dict = dict()

    try:
        for s in sightings:
            s_type = s.get('type', None)
            s_timestamp = int(s.get('date_sighting', None))
            s_source = s.get('source', None)
            if 'Organisation' in s:
                s_org_name = s['Organisation'].get('name', None)
                s_org_uuid = s['Organisation'].get('uuid', None)

            s_key = prefix + "sight_t" + str(s_type)
            if f'{s_key}_count' in sighting_metric_dict:
                sighting_metric_dict[f'{s_key}_count'] += 1
            else:
                sighting_metric_dict[f'{s_key}_count'] = 1

            if sighting_metric_dict.get(f'{s_key}_first_sight', 9999999999) > s_timestamp:
                sighting_metric_dict[f'{s_key}_first_sight'] = s_timestamp
                sighting_metric_dict[f'{s_key}_first_org_name'] = s_org_name
                sighting_metric_dict[f'{s_key}_first_org_uuid'] = s_org_uuid
                sighting_metric_dict[f'{s_key}_first_source'] = s_source

            if sighting_metric_dict.get(f'{s_key}_last_sight', 1) < s_timestamp:
                sighting_metric_dict[f'{s_key}_last_sight'] = s_timestamp
                sighting_metric_dict[f'{s_key}_last_org_name'] = s_org_name
                sighting_metric_dict[f'{s_key}_last_org_uuid'] = s_org_uuid
                sighting_metric_dict[f'{s_key}_last_source'] = s_source
    except Exception:
        pass

    return sighting_metric_dict


def map_attribute_table(helper, attributes, config):
    attribute_mapping = {
        'category': 'category',
        'comment': 'comment',
        'deleted': 'deleted',
        'distribution': 'attribute_distribution',
        'event_id': 'event_id',
        'event_uuid': 'event_uuid',
        'first_seen': 'first_seen',
        'id': 'attribute_id',
        'last_seen': 'last_seen',
        'object_id': 'object_id',
        'object_relation': 'object_relation',
        'sharing_group_id': 'sharing_group_id',
        'timestamp': 'timestamp',
        'to_ids': 'to_ids',
        'type': 'type',
        'uuid': 'attribute_uuid',
        'value': 'value',
    }

    result_list = list()
    misp_type_list = list()

    expand_object = config.get('expand_object', False)
    host = config.get('host', "unknown_host")
    include_sightings = config.get('include_sightings', True)
    pipesplit = config.get('pipesplit', True)
    prefix = config.get('prefix', "misp_")
    
    for a in attributes:
        attribute = dict()
        for key, value in attribute_mapping.items():
            if key in a:
                attribute[f'{prefix}{value}'] = a[key]
        if 'Event' in a:
            e = a['Event']
            event_mapping = {
                'distribution': 'event_distribution',
                'id': 'event_id',
                'info': 'event_info',
                'org_id': 'org_id',
                'orgc_id': 'orgc_id',
                'publish_timestamp': 'publish_timestamp',
                'uuid': 'event_uuid',
            }
            for key, value in event_mapping.items():
                if key in e:
                    attribute[f'{prefix}{value}'] = e[key]

        if include_sightings and 'Sighting' in a:
            attribute.update(map_sighting_table(helper, list(a.pop('Sighting')), config))

        attribute[f'{prefix}host'] = host
        attribute[f'{prefix}tag'] = list()
        tag_value = a.pop('Tag', None)
        if isinstance(tag_value, list):
            for tag in tag_value:
                attribute[f'{prefix}tag'].append(tag.get('name').strip())
        elif isinstance(tag_value, dict):
            attribute[f'{prefix}tag'].append(tag_value.get('name').strip())
        attribute[f'{prefix}timestamp'] = int(attribute[f'{prefix}timestamp'])

        # combined: not part of an object
        # AND multivalue attribute AND to be split
        if int(a['object_id']) == 0 \
           and '|' in a['type'] \
           and pipesplit is True:
            mv_type_list = str(a['type']).split('|')
            mv_value_list = str(a['value']).split('|')
            left_v = attribute.copy()
            left_v[f'{prefix}type'] = str(mv_type_list.pop())
            left_v[f'{prefix}value'] = str(mv_value_list.pop())
            result_list.append(left_v)
            if left_v[f'{prefix}type'] not in misp_type_list:
                misp_type_list.append(left_v[f'{prefix}type'])
            right_v = attribute.copy()
            right_v[f'{prefix}type'] = str(mv_type_list.pop())
            right_v[f'{prefix}value'] = str(mv_value_list.pop())
            result_list.append(right_v)
            if right_v[f'{prefix}type'] not in misp_type_list:
                misp_type_list.append(right_v[f'{prefix}type'])
        else:
            result_list.append(attribute)
            if attribute[f'{prefix}type'] not in misp_type_list:
                misp_type_list.append(attribute[f'{prefix}type'])
    del attributes
    helper.log_info(json.dumps(misp_type_list))

    # consolidate attribute values under output table
    output_dict = dict()
    for r in result_list:
        if expand_object is False \
           and int(r[f'{prefix}object_id']) != 0:
            r_key = str(r[f'{prefix}event_id']) \
                + '_object_' + str(r[f'{prefix}object_id'])
        else:
            r_key = str(r[f'{prefix}event_id']) + \
                '_' + str(r[f'{prefix}attribute_id'])

        if r_key not in output_dict:
            for t in misp_type_list:
                misp_t = prefix + t.replace('-', '_').replace('|', '_p_')
                # v[misp_t] = list()
                if t == r[f'{prefix}type']:
                    # v[misp_t].append(r[f'{prefix}value'])
                    r[misp_t] = str(r[f'{prefix}value'])
            output_dict[r_key] = r
        else:
            v = output_dict[r_key]
            if v[f'{prefix}object_id'] == 0:  # this is a composed attribute
                misp_t = prefix + r[f'{prefix}type'].replace('-', '_').replace('|', '_p_')
                if misp_t in v:
                    if not isinstance(v[misp_t], list):
                        v[misp_t] = make_list(helper, v[misp_t])
                    v[misp_t].append(str(r[f'{prefix}value']))  # set value for type
                else:
                    v[misp_t] = str(r[f'{prefix}value'])
                v[f'{prefix}type'] = str(r[f'{prefix}type'].replace('_', '-') + '|' + v[f'{prefix}type'].replace('_', '-'))
                v[f'{prefix}value'] = str(r[f'{prefix}value'] + '|' + v[f'{prefix}value'])
            else:  # object to merge
                misp_t = prefix + r[f'{prefix}type'].replace('-', '_')
                if misp_t in v:
                    if not isinstance(v[misp_t], list):
                        v[misp_t] = make_list(helper, v[misp_t])
                    v[misp_t].append(r[f'{prefix}value'])  # set value for type
                else:
                    v[misp_t] = str(r[f'{prefix}value'])
                for orig_key, misp_key in attribute_mapping.items():
                    misp_key = prefix + misp_key
                    if misp_key in r:
                        if misp_key in v:
                            if not isinstance(v[misp_key], list):
                                v[misp_key] = make_list(helper, v[misp_key])
                            if r[misp_key] not in v[misp_key]:
                                v[misp_key].append(r[misp_key])
                        else:
                            v[misp_key] = r[misp_key]

                tag_list = v[f'{prefix}tag']
                for tag in r[f'{prefix}tag']:
                    if tag not in tag_list:
                        tag_list.append(tag)
                v[f'{prefix}tag'] = tag_list

            output_dict[r_key] = v

    return list(output_dict.values())


def get_events(helper, connection, config, body_dict):
    response = list()
    response_count = 0

    body_dict['includeSightingdb'] = config['include_sightings']
    if config['page'] == 0 and config['limit'] != 0:
        request_loop = True
        body_dict['limit'] = config['limit']
        body_dict['page'] = 1
        while request_loop:
            iter_response = urllib_request(
                helper,
                connection,
                'POST',
                config['misp_url'],
                body_dict,
                config)
            if 'response' in iter_response:
                rlength = len(iter_response['response'])
                if rlength != 0:
                    for r_item in iter_response['response']:
                        event = r_item.get('Event')
                        if config['getioc'] is False:
                            event.pop('Attribute')
                            event.pop('Object')
                        if config['keep_galaxy'] is False:
                            event.pop('Galaxy')
                        if config['keep_related'] is False:
                            event.pop('RelatedEvent')
                        response.append(event)
                    helper.log_debug(
                        '[MC-801] request on page {} returned {} event(s); querying next page'
                        .format(body_dict['page'], rlength))
                    body_dict['page'] = body_dict['page'] + 1
                    response_count += rlength
                else:
                    helper.log_debug(
                        '[MC-801] request on page {} returned {} event.'
                        .format(body_dict['page'], rlength))
                    # last page is reached
                    request_loop = False
            else:
                request_loop = False
    else:
        body_dict['limit'] = config['limit']
        body_dict['page'] = config['page']
        iter_response = urllib_request(
            helper,
            connection,
            'POST',
            config['misp_url'],
            body_dict,
            config)
        if 'response' in iter_response:
            for r_item in iter_response['response']:
                event = r_item.get('Event')
                if config['getioc'] is False:
                    event.pop('Attribute')
                    event.pop('Object')
                if config['keep_galaxy'] is False:
                    event.pop('Galaxy')
                if config['keep_related'] is False:
                    event.pop('RelatedEvent')
                response.append(event)
            response_count = len(iter_response['response'])

    helper.log_info('[MC-802] response contains {} records'
                    .format(response_count))
    return response


def flatten_object(d, parent_key='', sep='_'):
    items = []
    if isinstance(d, dict):
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k.lower()}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_object(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    items.extend(flatten_object({f"{new_key}{sep}{i}": item}, '', sep=sep).items())
            else:
                items.append((new_key, v))
    elif isinstance(d, list):
        for i, item in enumerate(d):
            items.extend(flatten_object({f"{parent_key}{sep}{i}": item}, '', sep=sep).items())
    return dict(items)


def map_event_table(helper, events, config):
    # build output table and list of types
    result_list = list()
    attribute_limit = int(config.get('attribute_limit', 0))
    host = config.get('host',"unknown_host")
    prefix = config.get('prefix', "misp_")
    # process events and return a list of dict
    # if getioc=true each event entry contains a key Attribute
    # with a list of all attributes
    event_mapping = {
        'analysis': 'analysis', 
        'attribute_count': 'analysis_count',
        'date': 'event_date',
        'disable_correlation': 'disable_correlation',
        'distribution': 'distribution', 
        'extends_uuid': 'extends_uuid', 
        'id': 'event_id',
        'info': 'event_info',
        'locked': 'locked', 
        'proposal_email_lock': 'proposal_email_lock', 
        'publish_timestamp': 'publish_timestamp',
        'published': 'event_published',
        'sharing_group_id': 'sharing_group_id', 
        'threat_level_id': 'threat_level_id', 
        'timestamp': 'event_timestamp',
        'uuid': 'event_uuid',
        'value': 'value',
    }
    for e in events:
        event_dict = dict()
        for key, value in event_mapping.items():
            if key in e:
                event_dict[f'{prefix}{value}'] = e[key]
        event_org = e.get('Org')
        for org_key, org_value in event_org.items():
            event_dict[f'{prefix}org_{org_key}'] = org_value
        event_orgc = e.get('Orgc')
        for orgc_key, orgc_value in event_orgc.items():
            event_dict[f'{prefix}orgc_{orgc_key}'] = orgc_value

        if e.get('Galaxy'):
            event_dict[f'{prefix}galaxy'] = flatten_object(e.pop('Galaxy'), f'{prefix}galaxy')

        if e.get('RelatedEvent'):
            event_dict[f'{prefix}related'] = flatten_object(e.pop('RelatedEvent'), f'{prefix}related')

        event_dict[f'{prefix}host'] = host
        event_dict[f'{prefix}tag'] = list()
        tag_value = e.pop('Tag', None)
        if isinstance(tag_value, list):
            for tag in tag_value:
                event_dict[f'{prefix}tag'].append(tag.get('name').strip())
        elif isinstance(tag_value, dict):
            event_dict[f'{prefix}tag'].append(tag_value.get('name').strip())
        
        if 'Object' in e:
            for o in e['Object']:
                object_dict = dict()
                for o_key, o_value in o.items():
                    object_dict[f'{prefix}object_{o_key}'] = o_value
                object_dict.pop(f'{prefix}object_Attribute')
                object_dict.pop(f'{prefix}object_event_id')
                attributes = o.pop('Attribute', None)
                if attributes:
                    attribute_list = map_attribute_table(helper, attributes, config)
                    if attribute_list:
                        if attribute_limit > 0 and attribute_limit < len(attribute_list):
                            temp = attribute_list.copy()
                            attribute_list = temp[:attribute_limit]
                            helper.log_info(
                                '[MC-901] object attribute count is {} (was {} truncated to attribute_limit {})'
                                .format(len(attribute_list), len(temp), attribute_limit))
                        for a in attribute_list:
                            a.update(object_dict)
                            a.update(event_dict)
                            result_list.append(a)
        if 'Attribute' in e:
            attributes = e.pop('Attribute', None)
            if attributes:
                attribute_list = map_attribute_table(helper, attributes, config)
                if attribute_list:
                    if attribute_limit > 0 and attribute_limit < len(attribute_list):
                        temp = attribute_list.copy()
                        attribute_list = temp[:attribute_limit]
                        helper.log_info(
                            '[MC-902] attribute count is {} (was {} truncated to attribute_limit {})'
                            .format(len(attribute_list), len(temp), attribute_limit))
                for a in attribute_list:
                    a.update(event_dict)
                    result_list.append(a)
        if config['getioc'] is False:
            event_dict[f'{prefix}timestamp'] = event_dict[f'{prefix}event_timestamp'] 
            result_list.append(event_dict)    

    return result_list
