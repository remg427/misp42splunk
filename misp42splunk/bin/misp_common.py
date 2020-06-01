# coding=utf-8
import json
import logging
import os
from splunk.clilib import cli_common as cli
from io import open

__license__ = "LGPLv3"
__version__ = "3.1.11"
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
        _SPLUNK_PATH, 'etc', 'apps',
        app_name,
        'local',
        app_name + '_settings.conf'
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


def prepare_config(self, app_name):
    config_args = dict()
    # get MISP instance to be used
    misp_instance = self.misp_instance
    stanza_name = 'misp://' + misp_instance
    logging.info("stanza_name={}".format(stanza_name))
    # get MISP instance parameters
    # open local/inputs.conf into a dict:  app_config
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    inputs_conf_file = os.path.join(
        _SPLUNK_PATH, 'etc', 'apps',
        app_name,
        'local',
        'inputs.conf'
    )
    if os.path.exists(inputs_conf_file):
        inputsConf = cli.readConfFile(inputs_conf_file)
        foundStanza = False
        for name, content in list(inputsConf.items()):
            if stanza_name == str(name):
                app_config = content
                foundStanza = True
                logging.info(
                    'misp42splunk config: {}'.format(
                        json.dumps(app_config)
                    )
                )
        if not foundStanza:
            logging.error(
                "local/inputs.conf does not contain \
                settings for stanza: {}".format(stanza_name)
            )
            raise Exception(
                'local/inputs.conf does not contain \
                any stanza %s ', str(stanza_name)
            )
    else:
        logging.error(
            "local/inputs.conf does not exist. Please configure misp instances first."
        )
        raise Exception(
            'local/inputs.conf does not exist. Please configure an inputs entry for %s', misp_instance
        )
    # get clear version of misp_key
    storage_passwords = self.service.storage_passwords
    config_args['misp_key'] = None
    for credential in storage_passwords:
        # usercreds = {'username':credential.content.get('username'),
        # 'password':credential.content.get('clear_password')}
        username = credential.content.get('username')
        if misp_instance in username \
           and 'misp_key' in credential.content.get('clear_password'):
            misp_instance_key = json.loads(
                credential.content.get('clear_password'))
            config_args['misp_key'] = str(misp_instance_key['misp_key'])
            logging.info(
                'misp_key found for instance {}'.format(misp_instance)
            )
        if 'proxy' in username and 'misp' in username and \
                'proxy_password' in credential.content.get('clear_password'):
            proxy_password = str(json.loads(
                credential.content.get('clear_password')))
            logging.info('proxy_password found for misp42splunk')

    if config_args['misp_key'] is None:
        logging.error(
            'misp_key NOT found for instance \
            {}'.format(misp_instance)
        )
        raise Exception('misp_key NOT found for instance %s', misp_instance)
    # settings
    # save MISP settings stored in inputs.conf into config_arg
    misp_url = app_config['misp_url']
    if misp_url.startswith('https://'):
        config_args['misp_url'] = misp_url
        logging.info("config_args['misp_url'] {}".format(config_args['misp_url']))
    else:
        logging.error("misp_url must start with HTTPS. Please set a valid misp_url")
        exit(1)

    if int(app_config['misp_verifycert']) == 1:
        misp_ca_full_path = app_config.get('misp_ca_full_path', '')
        if misp_ca_full_path != '':
            config_args['misp_verifycert'] = misp_ca_full_path
        else:
            config_args['misp_verifycert'] = True
    else:
        config_args['misp_verifycert'] = False
    logging.info("config_args['misp_verifycert'] \
        {}".format(config_args['misp_verifycert']))

    config_args['proxies'] = dict()
    if int(app_config['misp_use_proxy']) == 1:
        settings_file = os.path.join(
            _SPLUNK_PATH, 'etc', 'apps',
            app_name,
            'local',
            app_name + '_settings.conf'
        )
        if os.path.exists(settings_file):
            app_settings = cli.readConfFile(settings_file)
            foundProxy = False
            for name, content in list(app_settings.items()):
                if 'proxy' in name:
                    proxy = content
                    foundProxy = True
                    logging.info("Successfully found proxy settings")
            if not foundProxy:
                logging.error("misp_use_proxy is True and local/misp42splunk_settings.conf does not contain settings for proxy")
                raise Exception('misp_use_proxy is True and local/misp42splunk_settings.conf does not contain settings for proxy')
        else:
            logging.error("misp_use_proxy is True and local/misp42splunk_settings.conf does not exist. Please configure misp42splunk first.")
            raise Exception("misp_use_proxy is True and local/misp42splunk_\
                settings.conf does not exist. \
                Please configure misp42splunk first.")
        if proxy:
            proxy_url = '://'
            if proxy['proxy_username'] not in [None, '']:
                proxy_url = proxy_url + proxy['proxy_username'] \
                    + ':' + proxy_password + '@'
            proxy_url = proxy_url + proxy['proxy_url'] + ':' \
                + proxy['proxy_port'] + '/'
            config_args['proxies'] = {
                "http": "http" + proxy_url,
                "https": "https" + proxy_url
            }

    # get client cert parameters
    if int(app_config['client_use_cert']) == 1:
        config_args['client_cert_full_path'] = \
            app_config['client_cert_full_path']
    else:
        config_args['client_cert_full_path'] = None
    logging.info("config_args['client_cert_full_path'] \
        {}".format(config_args['client_cert_full_path']))

    # test if client certificate file is readable
    if config_args['client_cert_full_path'] is not None:
        try:
            # open client_cert_full_path if exists and log.
            with open(config_args['client_cert_full_path'], 'rb'):
                logging.info('client_cert_full_path file at %s was successfully\
                 opened', str(config_args['client_cert_full_path']))
        except IOError:  # file misp_instances.csv not readable
            logging.error(
                'client_cert_full_path file at %s not readable',
                str(config_args['client_cert_full_path'])
            )
            raise Exception('client_cert_full_path file at %s not readable',
                            str(config_args['client_cert_full_path']))

    return config_args
