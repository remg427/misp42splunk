#!/usr/bin/env python
# coding=utf-8
#
# Extract IOC's from MISP
#
# Author: Xavier Mertens <xavier@rootshell.be>
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#

from __future__ import absolute_import, division, print_function, unicode_literals
import os
import sys
import ConfigParser
import requests
import json
from itertools import chain
from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators
import logging

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "4.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"

# try:
#    from utils import error, parse
# except ImportError:
#    raise Exception("Add the SDK repository to your PYTHONPATH to run the examples (e.g., export PYTHONPATH=~/splunk-sdk-python.")

@Configuration(requires_preop=False)

class mispioc(ReportingCommand):
    """ get the attributes from a MISP instance.
    ##Syntax
    .. code-block::
        | mispgetioc last=<number>(d|h|m)
        | mispgetioc event=<id>
    ##Description
    A count of the number of non-overlapping matches to the regular expression specified by `pattern` is computed for
    each record processed. The result is stored in the field specified by `fieldname`. If `fieldname` exists, its value
    is replaced. If `fieldname` does not exist, it is created. Event records are otherwise passed through to the next
    pipeline processor unmodified.
    ##Example
    Count the number of words in the `text` of each tweet in tweets.csv and store the result in `word_count`.
    .. code-block::
        | inputlookup tweets | countmatches fieldname=word_count pattern="\\w+" text
    """    
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


    eventid         = Option(require=False, validate=validators.Match("eventid",     r"^[0-9]+$"))
    last            = Option(require=False, validate=validators.Match("last",        r"^[0-9]+[hdm]$"))
    onlyids         = Option(require=False, validate=validators.Match("onlyids",     r"^[yYnN01]+$"))
    getuuid         = Option(require=False, validate=validators.Match("getuuid",     r"^[yYnN01]+$"))
    getorg          = Option(require=False, validate=validators.Match("getorg",      r"^[yYnN01]+$"))
    category        = Option(require=False)
    type            = Option(require=False)
    tags            = Option(require=False)
    not_tags        = Option(require=False)

    @Configuration()
    def map(self, records):
        # self.logger.debug('mispgetioc.map')
        return records

    def reduce(self, records):

        # Phase 1: Preparation

        # self.logger.debug('mispgetioc.reduce')
        _SPLUNK_PATH = os.environ['SPLUNK_HOME']

        # open misp.conf
        config_file = _SPLUNK_PATH + '/etc/apps/misp42splunk/local/misp.conf'
        mispconf = ConfigParser.RawConfigParser()
        mispconf.read(config_file)

        # Generate args
        my_args = {}
        # MISP instance parameters
        if self.mispsrv:
            my_args['mispsrv'] = self.mispsrv
            logging.debug('mispsrv as option, value is %s', my_args['mispsrv'])
        else:
            my_args['mispsrv'] = mispconf.get('mispsetup', 'mispsrv')
            logging.debug('misp.conf: mispsrv value is %s', my_args['mispsrv'])
        if self.mispkey:
            my_args['mispkey'] = self.mispkey
            logging.debug('mispkey as option, value is %s', my_args['mispkey'])
        else:
            my_args['mispkey'] = mispconf.get('mispsetup', 'mispkey')
            logging.debug('misp.conf: mispkey value is %s', my_args['mispkey'])
        if self.verify_cert:
            if self.verify_cert == 'Y' or self.verify_cert == 'y' or self.verify_cert == '1':
                my_args['verify_cert'] = True
            else:
                my_args['verify_cert'] = False                        
            logging.debug('verify_cert as option, value is %s', my_args['verify_cert'])
        else:
            my_args['verify_cert'] = mispconf.getboolean('mispsetup', 'sslcheck')
            logging.debug('misp.conf: sslcheck value is %s', my_args['verify_cert'])


        # build search JSON object
        limit = 1000
        other_page = True
        page = 1
        body_dict = { "returnFormat": "json", 
                      "withAttachments": False,
                      "limit": limit,
                      "deleted": False
                    }

        # check that ONE of mandatory fields is present
        if self.eventid and self.last:
            logging.error('Options "eventid" and "last" are mutually exclusive')
            raise Exception('Options "eventid" and "last" are mutually exclusive')
        elif self.eventid:
            body_dict['eventid'] = self.eventid
            my_args['mispsrv'] = my_args['mispsrv'] + '/events/restSearch'
            logging.info('Option "eventid" set with %s', body_dict['eventid'])
        elif self.last:
            body_dict['last'] = self.last
            my_args['mispsrv'] = my_args['mispsrv'] + '/attributes/restSearch'
            logging.info('Option "last" set with %s', body_dict['last'])
        else:
            logging.error('Missing "eventid" or "last" argument')
            raise Exception('Missing "eventid" or "last" argument')

        # set proper headers
        headers = {'Content-type': 'application/json'}
        headers['Authorization'] = my_args['mispkey']
        headers['Accept'] = 'application/json'


        #Search parameters: boolean and filter
        if self.onlyids == 'Y' or self.onlyids == 'y' or self.onlyids == '1':
            body_dict['to_ids'] = True
        if self.category is not None:
            my_args['category'] = self.category
        else:
            my_args['category'] = None
        if self.type is not None:
            my_args['type'] = self.type
        else:
            my_args['type'] = None
        if self.tags is not None:
            my_args['tags'] = self.tags
        else:
            my_args['tags'] = None
        if self.not_tags is not None:
            my_args['not_tags'] = self.not_tags
        else:
            my_args['not_tags'] = None
        
        while other_page:
            body_dict['page'] = page
            body = json.dumps(body_dict)
            # search 
            r = requests.post(my_args['mispsrv'], headers=headers, data=body, verify=my_args['verify_cert'])
            # check if status is anything other than 200; throw an exception if it is
            r.raise_for_status()
            # response is 200 by this point or we would have thrown an exception
            # print >> sys.stderr, "DEBUG MISP REST API response: %s" % response.json()
            response = r.json()
            if 'response' in response:
                if 'Attribute' in response['response']:
                    l = len(response['response']['Attribute'])
                    for a in response['response']['Attribute']:
                        v = {}
                        v["event_id"] = str(a["event_id"])
                        v["category"] = str(a["category"])
                        v["type"] = str(a["type"])
                        v["to_ids"] = str(a["to_ids"])
                        v["value"] = str(a["value"])
                        yield v
            if l < limit:
                other_page = False
            else:
                page = page + 1


if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)
    dispatch(mispioc, sys.argv, sys.stdin, sys.stdout, __name__)
