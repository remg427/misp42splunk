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


    eventid         = Option(
        doc = '''
        **Syntax:** **eventid=***id1(,id2,...)*
        **Description:**list of event ID(s). **eventid** and **last** are mutually exclusive''',
        require=False, validate=validators.Match("eventid",     r"^[0-9,]+$"))

    last            = Option(
        doc = '''
        **Syntax:** **last=***<int>d|h|m*
        **Description:**publication duration in day(s), hour(s) or minute(s). **eventid** and **last** are mutually exclusive''',
        require=False, validate=validators.Match("last",        r"^[0-9]+[hdm]$"))

    onlyids         = Option(
        doc = '''
        **Syntax:** **onlyids=***y|Y|n|N|0|1*
        **Description:**Boolean to search only attributes with the flag "to_ids" set to true.''',
        require=False, validate=validators.Match("onlyids",     r"^[yYnN01]+$"))

    category        = Option(
        doc = '''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    type            = Option(
        doc = '''
        **Syntax:** **type=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    tags            = Option(
        doc = '''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for. Wildcard is %.''',
        require=False)
    not_tags        = Option(
        doc = '''
        **Syntax:** **not_tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to exclude from results. Wildcard is %.''',
        require=False)

    getuuid         = Option(
        doc = '''
        **Syntax:** **getuuid=***y|Y|n|N|0|1*
        **Description:**Boolean to return attribute UUID.''',
        require=False, validate=validators.Match("getuuid",     r"^[yYnN01]+$"))
    getorg          = Option(
        doc = '''
        **Syntax:** **getorg=***y|Y|n|N|0|1*
        **Description:**Boolean to return the ID of the organisation that created the event.''',
        require=False, validate=validators.Match("getorg",      r"^[yYnN01]+$"))
    geteventtag     = Option(
        doc = '''
        **Syntax:** **geteventtag=***y|Y|n|N|0|1*
        **Description:**Boolean to return also event tag(s). By default only attribute tag(s) are returned.''',
        require=False, validate=validators.Match("geteventtag", r"^[yYnN01]+$"))

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
            event_criteria = {}
            event_list = self.eventid.split(",")
            event_criteria['OR'] = event_list
            body_dict['eventid'] = event_criteria
            logging.info('Option "eventid" set with %s', body_dict['eventid'])
        elif self.last:
            body_dict['last'] = self.last
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
        if self.geteventtag == 'Y' or self.geteventtag == 'y' or self.geteventtag == '1':
            body_dict['includeEventTags'] = True
        if self.category is not None:
            cat_criteria = {}
            cat_list = self.category.split(",")
            cat_criteria['OR'] = cat_list
            body_dict['category'] = cat_criteria
        if self.type is not None:
            type_criteria = {}
            type_list = self.type.split(",")
            type_criteria['OR'] = type_list
            body_dict['type'] = type_criteria
        if self.tags is not None or self.not_tags is not None:
            tags_criteria = {}
            if self.tags is not None:
                tags_list = self.tags.split(",")
                tags_criteria['OR'] = tags_list
            if self.not_tags is not None:
                tags_list = self.not_tags.split(",")
                tags_criteria['NOT'] = tags_list
            body_dict['tags'] = tags_criteria

        # output filter parameters
        if self.getuuid == 'Y' or self.getuuid == 'y' or self.getuuid == '1':
            my_args['getuuid'] = True
        else:
            my_args['getuuid'] = False
        if self.getorg == 'Y' or self.getorg == 'y' or self.getorg == '1':
            my_args['getorg'] = True
        else:
            my_args['getorg'] = False

        results = []
        while other_page:
            body_dict['page'] = page
            body = json.dumps(body_dict)
            logging.error('DEBUG MISP REST API REQUEST: %s', body)
            # search 
            my_args['mispurl'] = my_args['mispsrv'] + '/attributes/restSearch'
            r = requests.post(my_args['mispurl'], headers=headers, data=body, verify=my_args['verify_cert'])
            # check if status is anything other than 200; throw an exception if it is
            r.raise_for_status()
            # response is 200 by this point or we would have thrown an exception
            response = r.json()
            if 'response' in response:
                if 'Attribute' in response['response']:
                    l = len(response['response']['Attribute'])
                    for a in response['response']['Attribute']:
                        v = {}
                        v['category'] = str(a['category'])
                        v['event_id'] = str(a['event_id'])
                        v['object_id'] = str(a['object_id'])
                        v['type'] = str(a['type'])
                        v['timestamp'] = str(a['timestamp'])
                        v['to_ids'] = str(a['to_ids'])
                        v['value'] = str(a['value'])
                        # v['json'] = json.dumps(a)
                        # list tag(s) if any in CSV format
                        tag_delims = ''
                        tag_string = ''
                        if 'Tag' in a:
                            for tag in a['Tag']:
                                tag_string = tag_string + tag_delims + tag['name']
                                tag_delims = ','
                        v['tag'] = tag_string
                        # include attribute UUID if requested
                        if my_args['getuuid']:
                            v['uuid'] = str(a['uuid'])
                        # include ID of the organisation that created the attribute if requested
                        # in previous version this was the ORG name ==> create lookup
                        if 'Event' in a and my_args['getorg']:
                            v['orgc_id'] = str(a['Event']['orgc_id'])
                        results.append(v)

            if l < limit:
                other_page = False
            else:
                page = page + 1

        # add colums for each type in results
        typelist = []
        for r in results:
            if r['type'] not in typelist:
                typelist.append(r['type'])

        for r in results:
            v = r
            for t in typelist:
                if t == r['type']:
                    v[t] = r['value']
                else:
                    v[t] = ''
            yield v


if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.ERROR)
    dispatch(mispioc, sys.argv, sys.stdin, sys.stdout, __name__)
