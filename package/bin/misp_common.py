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
__version__ = "4.2.0"
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


def prepare_config(helper, app_name, misp_instance, storage_passwords, session_key=None):
    config_args = dict(
        misp_key=None,
        misp_url=None,
        proxy_url=None,
        misp_verifycert=False,
        client_cert_full_path=None
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
        helper.log_error("[MC-PC-E01] Unexpected status received {}".format(response.status))
        raise Exception("[MC-PC-E01] Unexpected status received %s", str(response.status))
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
    else:
        raise Exception("[MC-PC-E04] misp_url must start with https://. Please set a valid misp_url")
        return None

    p = '(?:http.*://)?(?P<host>[^:/ ]+).?(?P<port>[0-9]*).*'
    m = re.search(p, config_args['misp_url'])
    config_args['host_header'] = m.group('host')  # 'www.abc.com'

    if int(app_config.get('misp_verifycert', '0')) == 1:
        config_args['misp_verifycert'] = True

    misp_ca_full_path = app_config.get('misp_ca_full_path', '')
    if misp_ca_full_path != '':
        config_args['misp_ca_cert'] = misp_ca_full_path
        config_args['misp_verifycert'] = True

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


def misp_url_request(url_connection, method, url, body, headers):
    if method == "GET":
        r = url_connection.request('GET',
                                   url,
                                   headers=headers,
                                   fields=body
                                   )
    elif method == 'POST':
        encoded_body = json.dumps(body).encode('utf-8')
        r = url_connection.request('POST',
                                   url,
                                   headers=headers,
                                   body=encoded_body
                                   )
    elif method == "DELETE":
        r = url_connection.request('DELETE',
                                   url,
                                   headers=headers,
                                   fields=body
                                   )
    else:
        raise Exception(
            "Sorry, no valid method provided (GET/POST//DELETE)."
            " it was {}.".format(method)
        )
    return r


def urllib_init_pool(helper, config):

    if config['misp_verifycert'] is True:
        kwargs = {"cert_reqs": "CERT_REQUIRED"}
    else:
        kwargs = {"cert_reqs": "CERT_NONE"}

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
    try:

        r = misp_url_request(url_connection, method, misp_url, body, headers)

        if r.status in (200, 201, 204):
            helper.log_info(
                "[MC501] INFO POST request is successful. url={}, HTTP status={}".format(
                    misp_url, r.status)
            )
            data = json.loads(r.data.decode('utf-8'))  # return response from MISP (with proxy)
        else:
            helper.log_error(
                "[MC502] ERROR POST request failed. url={}, HTTP status={}".format(
                    misp_url, r.status)
            )
            data = {'_time': time.time(),
                    '_raw': json.loads("[MC302] ERROR POST request failed. url={}, HTTP status={}".format(
                        misp_url, config['misp_verifycert'], r.status))
                    }
    except Exception as e:  # failed to execute request
        data = {'_time': time.time(),
                '_raw': "[MC503] DEBUG urlib3 {} request failed error={} url={}".format(
                method, e, misp_url)
                }

    return data
