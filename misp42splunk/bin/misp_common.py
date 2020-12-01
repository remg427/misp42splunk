# coding=utf-8
import json
import logging
import os
from splunk.clilib import cli_common as cli
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


def prepare_config(helper, app_name, misp_instance, storage_passwords):
    config_args = dict()
    # get MISP instance to be used
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    misp_instances_file = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps', app_name,
        'local', app_name + '_instances.conf'
    )
    if os.path.exists(misp_instances_file):
        inputsConf = cli.readConfFile(misp_instances_file)
        foundStanza = False
        for name, content in list(inputsConf.items()):
            if misp_instance == str(name):
                app_config = content
                foundStanza = True
        if not foundStanza:
            raise Exception(
                "local/misp42splunk_instances.conf does not contain "
                "any stanza {} ".format(misp_instance)
            )
            return None
    else:
        raise Exception(
            "local/misp42splunk_instances.conf does not exist. Please "
            "configure an inputs entry for {}".foremat(misp_instance)
        )
        return None

    # save MISP settings stored in misp42splunk_instances_file into config_arg
    misp_url = str(app_config['misp_url']).rstrip('/')
    if misp_url.startswith('https://'):
        config_args['misp_url'] = misp_url
    else:
        raise Exception(
            "[MC203] misp_url must start with https://. "
            "Please set a valid misp_url"
        )
        return None

    if int(app_config['misp_verifycert']) == 1:
        misp_ca_full_path = app_config.get('misp_ca_full_path', '')
        if misp_ca_full_path != '':
            config_args['misp_verifycert'] = misp_ca_full_path
        else:
            config_args['misp_verifycert'] = True
    else:
        config_args['misp_verifycert'] = False

    # get client cert parameters
    if int(app_config['client_use_cert']) == 1:
        config_args['client_cert_full_path'] = \
            app_config['client_cert_full_path']
    else:
        config_args['client_cert_full_path'] = None

    # test if client certificate file is readable
    if config_args['client_cert_full_path'] is not None:
        try:
            # open client_cert_full_path if exists and log.
            with open(config_args['client_cert_full_path'], 'rb'):
                helper.log_info(
                    "client_cert_full_path file at {} was successfully opened"
                    .format(config_args['client_cert_full_path'])
                )
        except IOError:  # file misp_instances.csv not readable
            helper.log_error(
                "[MC204] client_cert_full_path file at {} not readable"
                .format(config_args['client_cert_full_path'])
            )
            raise Exception(
                "client_cert_full_path file at {} not readable"
                .format(config_args['client_cert_full_path'])
            )
            return None

    # get clear version of misp_key
    config_args['misp_key'] = None
    proxy_clear_password = None
    for credential in storage_passwords:
        # usercreds = {'username':credential.content.get('username'),
        # 'password':credential.content.get('clear_password')}
        username = credential.content.get('username')
        if misp_instance in username:
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
        raise Exception(
            "misp_key NOT found for instance {}".format(misp_instance)
        )
        return None

    # get proxy parameters if any
    config_args['proxies'] = dict()
    if int(app_config['misp_use_proxy']) == 1:
        proxy = None
        settings_file = os.path.join(
            _SPLUNK_PATH, 'etc', 'apps', app_name,
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
