#!/usr/bin/python
#
# Extract IOC's from MISP
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

import splunk.admin as admin
import splunk.entity as en
import os
import csv
import logging
# import your required python modules

'''
Copyright (C) 2005 - 2010 Splunk Inc. All Rights Reserved.
Description:  This skeleton python script handles the parameters in the configuration page.

      handleList method: lists configurable parameters in the configuration page
      corresponds to handleractions = list in restmap.conf

      handleEdit method: controls the parameters and saves the values
      corresponds to handleractions = edit in restmap.conf

'''

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "2.2.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


class ConfigApp(admin.MConfigHandler):
  '''
  Set up supported arguments
  '''
  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['misp_url', 'misp_key', 'misp_verifycert', 'misp_use_proxy', 'client_use_cert', 'client_cert_full_path', 'http_proxy', 'https_proxy']:
        self.supportedArgs.addOptArg(arg)

  '''
  Read the initial values of the parameters from the custom file
      misp.conf, and write them to the setup page.

  If the app has never been set up,
      uses .../app_name/default/misp.conf.

  If app has been set up, looks at
      .../local/misp.conf first, then looks at
      .../default/misp.conf only if there is no value for a field in .../local/misp.conf

  For boolean fields, may need to switch the true/false setting.

  For text fields, if the conf file says None, set to the empty string.
  '''

  def handleList(self, confInfo):
    confDict = self.readConf("misp")
    if None != confDict:
      for stanza, settings in confDict.items():
        for key, val in settings.items():
          if key in ['misp_verifycert','client_use_cert','misp_use_proxy']:
            if int(val) == 1:
              val = '1'
            else:
              val = '0'
          if key in ['misp_url', 'misp_key', 'client_cert_full_path', 'http_proxy', 'https_proxy'] and val in [None, '']:
            val = ''
          confInfo[stanza].append(key, val)

  '''
  After user clicks Save on setup page, take updated parameters,
  normalize them, and save them somewhere
  '''
  def handleEdit(self, confInfo):
    #name = self.callerArgs.id
    #args = self.callerArgs
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)

    if int(self.callerArgs.data['misp_verifycert'][0]) == 1:
      self.callerArgs.data['misp_verifycert'][0] = '1'
      misp_verifycert = True
    else:
      self.callerArgs.data['misp_verifycert'][0] = '0'
      misp_verifycert = False
    if int(self.callerArgs.data['client_use_cert'][0]) == 1:
      self.callerArgs.data['client_use_cert'][0] = '1'
      client_use_cert = True
    else:
      self.callerArgs.data['client_use_cert'][0] = '0'
      client_use_cert = False
    if int(self.callerArgs.data['misp_use_proxy'][0]) == 1:
      self.callerArgs.data['misp_use_proxy'][0] = '1'
      misp_use_proxy = True
    else:
      self.callerArgs.data['misp_use_proxy'][0] = '0'
      misp_use_proxy = False

    if self.callerArgs.data['misp_url'][0] in [None, '']:
      self.callerArgs.data['misp_url'][0] = ''

    if self.callerArgs.data['misp_key'][0] in [None, '']:
      self.callerArgs.data['misp_key'][0] = ''

    if self.callerArgs.data['client_cert_full_path'][0] in [None, '']:
      self.callerArgs.data['client_cert_full_path'][0] = ''

    if self.callerArgs.data['http_proxy'][0] in [None, '']:
      self.callerArgs.data['http_proxy'][0] = ''

    if self.callerArgs.data['https_proxy'][0] in [None, '']:
      self.callerArgs.data['https_proxy'][0] = ''

#    Since we are using a conf file to store parameters,
#    write them to the [mispsetup] stanza
#    in app_name/local/misp.conf

    self.writeConf('misp', 'mispsetup', self.callerArgs.data)

#   Write also parameters under misp42splunk/lookups/misp_instances.csv
#   header row: misp_instance,misp_url,misp_key,misp_verifycert,misp_use_proxy,description,client_use_cert,client_cert_full_path
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']
    misp_instances = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'lookups' + os.sep + 'misp_instances.csv'
    try:
        with open(misp_instances, 'rb') as file_object:  # open misp_instances.csv if exists and load content.
            csv_reader = csv.reader(file_object)
            header_row = next(csv_reader)
            extend_misp_instances = False
            if 'client_use_cert' not in header_row:
              header_row = ['misp_instance','misp_url','misp_key','misp_verifycert','misp_use_proxy','description','client_use_cert','client_cert_full_path']
              extend_misp_instances = True
            instances = []
            for row in csv_reader:
              if 'default' in row:
                instances.append(['default', self.callerArgs.data['misp_url'][0], self.callerArgs.data['misp_key'][0], misp_verifycert, misp_use_proxy, 'default MISP instance defined at MISP42 app setup', client_use_cert, self.callerArgs.data['client_cert_full_path'][0]])
              else:
                if extend_misp_instances is True:
                  row.extend((False,''))
                instances.append(row)
    except IOError : # file misp_instances.csv doesn't exists so create empty instances
        header_row = ['misp_instance','misp_url','misp_key','misp_verifycert','misp_use_proxy','description','client_use_cert','client_cert_full_path']
        instance = ['default', self.callerArgs.data['misp_url'][0], self.callerArgs.data['misp_key'][0], misp_verifycert, misp_use_proxy, 'default MISP instance defined at MISP42 app setup', client_use_cert, self.callerArgs.data['client_cert_full_path'][0]]
        instances = []
        instances.append(instance)

    # overwrite to the file
    try:
        with open(misp_instances, 'wb') as file_object:  # open misp_instances.csv if exists and load content.
            csv_writer = csv.writer(file_object, delimiter=',')
            csv_writer.writerow(header_row)
            for instance in instances:
              csv_writer.writerow(instance)
    except IOError : # file misp_instances.csv doesn't exists so create empty instances
      logging.error("FATAL %s could not be opened in write mode", misp_instances)


# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)
