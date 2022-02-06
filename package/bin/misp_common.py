# coding=utf-8
import json
import os
from splunk.clilib import cli_common as cli
import splunklib
from io import open

__license__ = "LGPLv3"
__version__ = "4.0.0"
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
    config_args = dict()
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

    if int(app_config.get('misp_verifycert', '0')) == 1:
        misp_ca_full_path = app_config.get('misp_ca_full_path', '')
        if misp_ca_full_path != '':
            config_args['misp_verifycert'] = misp_ca_full_path
        else:
            config_args['misp_verifycert'] = True
    else:
        config_args['misp_verifycert'] = False

    # get client cert parameters
    if int(app_config.get('client_use_cert', '0')) == 1:
        config_args['client_cert_full_path'] = app_config.get('client_cert_full_path', 'no_path')
    else:
        config_args['client_cert_full_path'] = None

    # test if client certificate file is readable
    if config_args['client_cert_full_path'] is not None:
        try:
            # open client_cert_full_path if exists and log.
            with open(config_args['client_cert_full_path'], 'rb'):
                helper.log_info(
                    "client_cert_full_path file at {} was successfully opened".format(config_args['client_cert_full_path']))
        except IOError:  # file misp_instances.csv not readable
            helper.log_error(
                "[MC-PC-E05] client_cert_full_path file at {} not readable".format(config_args['client_cert_full_path'])
            )
            raise Exception(
                "[MC-PC-E05] client_cert_full_path file at {} not readable".format(config_args['client_cert_full_path'])
            )
            return None

    # get clear version of misp_key and proxy password
    config_args['misp_key'] = None
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
    config_args['proxies'] = dict()
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
            proxy_url = '://'
            if 'proxy_username' in proxy \
               and proxy_clear_password is not None:
                if proxy['proxy_username'] not in ['', None]:
                    proxy_url = proxy_url + \
                        proxy['proxy_username'] + ':' \
                        + proxy_clear_password + '@'
            proxy_url = proxy_url + proxy['proxy_hostname'] + \
                ':' + proxy['proxy_port'] + '/'
            config_args['proxies'] = {
                "http": "http" + proxy_url,
                "https": "https" + proxy_url
            }

    return config_args
