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
                "any stanza %s ", str(misp_instance)
            )
            return None
    else:
        raise Exception(
            "local/misp42splunk_instances.conf does not exist. Please "
            "configure an inputs entry for %s", misp_instance
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
                logging.info(
                    "client_cert_full_path file at %s was successfully opened",
                    str(config_args['client_cert_full_path'])
                )
        except IOError:  # file misp_instances.csv not readable
            logging.error(
                "[MC204] client_cert_full_path file at %s not readable",
                str(config_args['client_cert_full_path'])
            )
            raise Exception(
                "client_cert_full_path file at %s not readable",
                str(config_args['client_cert_full_path'])
            )
            return None

    # get proxy parameters if any
    config_args['proxies'] = dict()
    if int(app_config['misp_use_proxy']) == 1:
        proxy = helper.get_proxy()
        if proxy:
            proxy_url = '://'
            if 'proxy_username' in proxy:
                if proxy['proxy_username'] not in ['', None]:
                    proxy_url = proxy_url + \
                        proxy['proxy_username'] + ':' \
                        + proxy['proxy_password'] + '@'
            proxy_url = proxy_url + proxy['proxy_url'] + \
                ':' + proxy['proxy_port'] + '/'
            config_args['proxies'] = {
                "http": "http" + proxy_url,
                "https": "https" + proxy_url
            }

    # get clear version of misp_key
    config_args['misp_key'] = None
    for credential in storage_passwords:
        # usercreds = {'username':credential.content.get('username'),
        # 'password':credential.content.get('clear_password')}
        username = credential.content.get('username')
        if misp_instance in username \
           and 'misp_key' in credential.content.get('clear_password'):
            misp_instance_key = json.loads(
                credential.content.get('clear_password')
            )
            config_args['misp_key'] = str(misp_instance_key['misp_key'])

    if config_args['misp_key'] is None:
        raise Exception(
            "misp_key NOT found for instance %s", misp_instance
        )
        return None
    # settings

    return config_args
