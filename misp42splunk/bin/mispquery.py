#!/usr/bin/env python
# coding=utf-8
#
# search for value in MISP and add some fields to the pipeline
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#

import os
import sys
import ConfigParser
import requests
import json
from requests.auth import HTTPBasicAuth
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration, Option, validators

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"

@Configuration(local=True)

class MispQueryCommand(StreamingCommand):
    """ search in MISP for attributes matching the value of fieldd

    ##Syntax

    .. code-block::
        mispquery field=<field> onlyids=y|n

    ##Description

        body = {"returnFormat": "json",
                "value": "optional",
                "type": "optional",
                "category": "optional",
                "org": "optional",
                "tags": "optional",
                "from": "optional",
                "to": "optional",
                "last": "optional",
                "eventid": "optional",
                "withAttachments": "optional",
                "uuid": "optional",
                "publish_timestamp": "optional",
                "timestamp": "optional",
                "enforceWarninglist": "optional",
                "to_ids": "optional",
                "deleted": "optional",
                "includeEventUuid": "optional",
                "event_timestamp": "optional",
                "threat_level_id": "optional"
                }
    
    ##Example

    Search in MISP for value of fieldname r_ip (remote IP in proxy logs).

    .. code-block::
         * | mispquery fieldname=r_ip

    """

    field = Option(
        doc='''
        **Syntax:** **field=***<fieldname>*
        **Description:**Name of the field containing the value to search for.''',
        require=True, validate=validators.Fieldname())

    onlyids = Option(
        doc='''
        **Syntax:** **onlyids=***<y|n>*
        **Description:** Boolean to search only attributes with to_ids set''',
        require=False, validate=validators.Match("onlyids", r"^[yYnN01]+$"))

    comment = Option(
        doc='''
        **Syntax:** **comment=***<y|n>*
        **Description:** Boolean to return comments''',
        require=False, validate=validators.Match("onlyids", r"^[yYnN01]+$"))

# Superseede MISP instance for this search
    mispsrv = Option(
        doc='''
        **Syntax:** **mispsrv=***<MISP URL>*
        **Description:**URL of MISP instance.''',
        require=False, validate=validators.Match("mispsrv", r"^https?:\/\/[0-9a-zA-Z\-\.]+(?:\:\d+)?$"))

    mispkey = Option(
        doc='''
        **Syntax:** **mispkey=***<AUTH_KEY>*
        **Description:**MISP API AUTH KEY.''',
        require=False, validate=validators.Match("mispkey", r"^[0-9a-zA-Z]{40}$"))

    verify_cert = Option(
        doc = '''
        **Syntax:** **verify_cert=***<y|n>*
        **Description:**Verify or not MISP certificate.''',
        require=False, validate=validators.Match("verify_cert", r"^[yYnN01]$"))


    def stream(self, records):
        # open misp.conf
        _SPLUNK_PATH = os.environ['SPLUNK_HOME']
        config_file = _SPLUNK_PATH + '/etc/apps/misp42splunk/local/misp.conf'
        mispconf = ConfigParser.RawConfigParser()
        mispconf.read(config_file)

        # Generate args
        my_args = {}
        # MISP instance parameters
        if self.mispsrv:
            my_args['mispsrv'] = self.mispsrv + '/attributes/restSearch'
#            logging.info('mispsrv as option, value is %s', my_args['mispsrv'])
        else:
            my_args['mispsrv'] = mispconf.get('mispsetup', 'mispsrv') + '/attributes/restSearch'
#            logging.debug('misp.conf: mispsrv value is %s', my_args['mispsrv'])
        if self.mispkey:
            my_args['mispkey'] = self.mispkey
#            logging.info('mispkey as option, value is %s', my_args['mispkey'])
        else:
            my_args['mispkey'] = mispconf.get('mispsetup', 'mispkey')
#            logging.debug('misp.conf: mispkey value is %s', my_args['mispkey'])
        if self.verify_cert:
            if self.verify_cert == 'Y' or self.verify_cert == 'y' or self.verify_cert == '1':
                my_args['verify_cert'] = True
            else:
                my_args['verify_cert'] = False                        
#            logging.info('verify_cert as option, value is %s', my_args['verify_cert'])
        else:
            my_args['verify_cert'] = mispconf.getboolean('mispsetup', 'sslcheck')
#            logging.debug('misp.conf: sslcheck value is %s', my_args['verify_cert'])

        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['mispkey']
        headers['Accept'] = 'application/json'

        fieldname = str(self.field)
        if self.onlyids == 'Y' or self.onlyids == 'y' or self.onlyids == '1':
            to_ids = True
        else:
            to_ids = False
        if self.comment == 'Y' or self.comment == 'y' or self.comment == '1':
            get_comment = True
        else:
            get_comment = False

        for record in records:
            if fieldname in record:
                value = record.get(fieldname, None)
                if value is not None:
                    body_dict = { "returnFormat": "json"}
                    body_dict['value'] = str(value)
                    body_dict['withAttachments'] = "false",
                    if to_ids:
                        body_dict['to_ids'] = "True"
                    
                    body = json.dumps(body_dict)
                    misp_type = ''
                    misp_value = ''
                    misp_to_ids = ''
                    misp_category = ''
                    misp_uuid = ''
                    misp_event_id = ''
                    misp_comment = ''
                    delimns = ''
                    # post alert
                    r = requests.post(my_args['mispsrv'], headers=headers, data=body, verify=False)
                    # check if status is anything other than 200; throw an exception if it is
                    r.raise_for_status()
                    # response is 200 by this point or we would have thrown an exception
                    # print >> sys.stderr, "DEBUG MISP REST API response: %s" % response.json()
                    response = r.json()
                    if 'response' in response:
                        if 'Attribute' in response['response']:
                            record['misp_json'] = response['response']['Attribute']
                            for a in response['response']['Attribute']:
                                misp_type = misp_type + delimns + str(a['type'])
                                misp_value = misp_value + delimns + str(a['value'])
                                misp_to_ids = misp_to_ids + delimns + str(a['to_ids'])
                                misp_category = misp_category + delimns + str(a['category'])
                                misp_uuid = misp_uuid + delimns + str(a['uuid'])
                                misp_event_id = misp_event_id + delimns + str(a['event_id'])
                                if get_comment:
                                    misp_comment = misp_comment + delimns + str(a['comment'])
                                delimns = ','
                            record['misp_type'] = misp_type
                            record['misp_value'] = misp_value
                            record['misp_to_ids'] = misp_to_ids
                            record['misp_category'] = misp_category
                            record['misp_uuid'] = misp_uuid
                            record['misp_event_id'] = misp_event_id
                            if get_comment:
                                record['misp_comment'] = misp_comment

            yield record

if __name__ == "__main__":
    dispatch(MispQueryCommand, sys.argv, sys.stdin, sys.stdout, __name__)