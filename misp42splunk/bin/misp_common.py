#!/usr/bin/env python
# coding=utf-8
#__author__     = "Remi Seguy"

import csv
import json
import logging
import os
from splunk.clilib import cli_common as cli

__license__    = "LGPLv3"
__version__    = "2.2.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def prepare_config(self):
    # Generate confg_args
    config_args = {}
    # open misp.conf
    mispconf = cli.getConfStanza('misp','mispsetup')        
    # get proxy parameters if any
    http_proxy  = mispconf.get('http_proxy', '')
    https_proxy = mispconf.get('https_proxy', '')
    if http_proxy != '' and https_proxy != '':
        config_args['proxies'] = {
            "http": http_proxy,
            "https": https_proxy
        }
    else:
        config_args['proxies'] = {}
    # MISP instance parameters
    # get specific misp url and key if any (and misp_verifycert)
    if self.misp_url and self.misp_key:
        config_args['misp_url'] = self.misp_url
        logging.info('misp_url as option, value is %s', config_args['misp_url'])
        config_args['misp_key'] = self.misp_key
        logging.info('misp_key as option, value is %s', config_args['misp_key'])
        if self.misp_verifycert:
            config_args['misp_verifycert'] = self.misp_verifycert
        else:
            config_args['misp_verifycert'] = False
        logging.info('misp_verifycert as option, value is %s', config_args['misp_verifycert'])
        config_args['client_cert_full_path'] = None
        logging.info('client_cert_full_path value is %s', str(config_args['client_cert_full_path']))
    elif self.misp_instance:
        logging.info('misp_instance as option, value is %s', self.misp_instance)
        # get params from lookups/misp_instances.csv
        _SPLUNK_PATH = os.environ['SPLUNK_HOME']
        misp_instances = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'lookups' + os.sep + 'misp_instances.csv'
        found_instance = False
        try:
            with open(misp_instances, 'rb') as file_object:  # open misp_instances.csv if exists and load content.
                csv_reader = csv.DictReader(file_object)
                for row in csv_reader:
                    logging.debug('row, value is %s', row)
                    if row['misp_instance'] == self.misp_instance:
                        found_instance = True
                        # get MISP instance parameters
                        config_args['misp_url'] = row['misp_url']
                        logging.info('misp_instance: misp_url value is %s', config_args['misp_url'])
                        config_args['misp_key'] = row['misp_key']
                        logging.info('misp_instance: misp_key value is %s', config_args['misp_key'])
                        if row['misp_verifycert'] == 'True':
                            config_args['misp_verifycert'] = True
                        else:
                            config_args['misp_verifycert'] = False
                        logging.info('misp_instance: misp_verifycert value is %s', config_args['misp_verifycert'])
                        # adjust proxy settings if not used
                        if row['misp_use_proxy'] == 'False':
                            config_args['proxies'] = {}
                        logging.info('misp.conf: misp_use_proxy value is %s', row['misp_use_proxy'])
                        # get client cert parameters
                        if row['client_use_cert'] == 'True':
                            config_args['client_cert_full_path'] = row['client_cert_full_path']
                        else:
                            config_args['client_cert_full_path'] = None
                        logging.info('client_cert_full_path value is %s', str(config_args['client_cert_full_path']))  
        except IOError : # file misp_instances.csv not readable
            logging.error('file misp_instances.csv not readable')
            raise Exception('file misp_instances.csv not readable')
        if found_instance is False:
            logging.error('misp_instance name %s not found', self.misp_instance)
            raise Exception('misp_instance name %s not found' % self.misp_instance)
    else:
        # get MISP settings stored in misp.conf
        config_args['misp_url'] = mispconf.get('misp_url')
        logging.info('misp.conf: misp_url value is %s', config_args['misp_url'])
        config_args['misp_key'] = mispconf.get('misp_key')
        logging.info('misp.conf: misp_key value is %s', config_args['misp_key'])
        if int(mispconf.get('misp_verifycert')) == 1:
            config_args['misp_verifycert'] = True
        else:
            config_args['misp_verifycert'] = False
        logging.info('misp.conf: misp_verifycert value is %s', config_args['misp_verifycert'])
        # get client cert parameters
        if int(mispconf.get('client_use_cert')) == 1:
            config_args['client_cert_full_path'] = mispconf.get('client_cert_full_path')
        else:
            config_args['client_cert_full_path'] = None
        logging.info('client_cert_full_path value is %s', str(config_args['client_cert_full_path']))
        if int(mispconf.get('misp_use_proxy')) == 0:
            config_args['proxies'] = {}

    # test if client certificate file is readable
    if config_args['client_cert_full_path'] is not None:
        try:
            with open(config_args['client_cert_full_path'], 'rb') as file_object:  # open client_cert_full_path if exists and log.
                logging.info('client_cert_full_path file at %s was successfully opened', str(config_args['client_cert_full_path']))  
        except IOError : # file misp_instances.csv not readable
            logging.error('client_cert_full_path file at %s not readable', str(config_args['client_cert_full_path']))  
            raise Exception('client_cert_full_path file at %s not readable', str(config_args['client_cert_full_path']))


    logging.info('proxies dict is %s', json.dumps(config_args['proxies']))
    return config_args


