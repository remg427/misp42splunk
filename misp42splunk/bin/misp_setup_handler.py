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
# import your required python modules

'''
Copyright (C) 2005 - 2010 Splunk Inc. All Rights Reserved.
Description:  This skeleton python script handles the parameters in the configuration page.

      handleList method: lists configurable parameters in the configuration page
      corresponds to handleractions = list in restmap.conf

      handleEdit method: controls the parameters and saves the values 
      corresponds to handleractions = edit in restmap.conf

'''

class ConfigApp(admin.MConfigHandler):
  '''
  Set up supported arguments
  '''
  def setup(self):
    if self.requestedAction == admin.ACTION_EDIT:
      for arg in ['misp_url', 'misp_key', 'misp_verifycert', 'thehive_url', 'thehive_key', 'P3_PATH']:
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
          if key in ['misp_verifycert']:
            if int(val) == 1:
              val = '1'
            else:
              val = '0'
          if key in ['misp_url'] and val in [None, '']:
            val = ''
          if key in ['misp_key'] and val in [None, '']:
            val = ''
          if key in ['thehive_url'] and val in [None, '']:
            val = ''
          if key in ['theiveKey'] and val in [None, '']:
            val = ''
          if key in ['P3_PATH'] and val in [None, '']:
            val = ''
          confInfo[stanza].append(key, val)
          
  '''
  After user clicks Save on setup page, take updated parameters,
  normalize them, and save them somewhere
  '''
  def handleEdit(self, confInfo):
    name = self.callerArgs.id
    args = self.callerArgs
            
    if int(self.callerArgs.data['misp_verifycert'][0]) == 1:
      self.callerArgs.data['misp_verifycert'][0] = '1'
    else:
      self.callerArgs.data['misp_verifycert'][0] = '0'
    
    if self.callerArgs.data['misp_url'][0] in [None, '']:
      self.callerArgs.data['misp_url'][0] = ''  

    if self.callerArgs.data['misp_key'][0] in [None, '']:
      self.callerArgs.data['misp_key'][0] = ''  
        
    if self.callerArgs.data['thehive_url'][0] in [None, '']:
      self.callerArgs.data['thehive_url'][0] = ''  
        
    if self.callerArgs.data['thehive_key'][0] in [None, '']:
      self.callerArgs.data['thehive_key'][0] = ''  
        
    if self.callerArgs.data['P3_PATH'][0] in [None, '']:
      self.callerArgs.data['P3_PATH'][0] = ''  
      
#    Since we are using a conf file to store parameters, 
#    write them to the [mispsetup] stanza
#    in app_name/local/misp.conf  
        
    self.writeConf('misp', 'mispsetup', self.callerArgs.data)
      
# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)