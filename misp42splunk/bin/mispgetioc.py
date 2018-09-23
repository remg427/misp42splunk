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
import subprocess
import ConfigParser
import cPickle as pickle
from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators
import logging

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"

# try:
#    from utils import error, parse
# except ImportError:
#    raise Exception("Add the SDK repository to your PYTHONPATH to run the examples (e.g., export PYTHONPATH=~/splunk-sdk-python.")

@Configuration(requires_preop=False)

class mispgetioc(ReportingCommand):
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
    mispsrv         = Option(require=False, validate=validators.Match("mispsrv",     r"^https?:\/\/[0-9a-zA-Z\-\.]+(?:\:\d+)?$"))
    mispkey         = Option(require=False, validate=validators.Match("mispkey",     r"^[0-9a-zA-Z]{40}$"))
    sslcheck        = Option(require=False, validate=validators.Match("sslcheck",    r"^[yYnN01]$"))
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
        yield {}
        return

    def reduce(self, records):

        # Phase 1: Preparation

        # self.logger.debug('mispgetioc.reduce')
        if self.sslcheck == None:
            self.sslcheck = 'n'

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
            logging.info('mispsrv as option, value is %s', my_args['mispsrv'])
        else:
            my_args['mispsrv'] = mispconf.get('mispsetup', 'mispsrv')
            logging.debug('misp.conf: mispsrv value is %s', my_args['mispsrv'])
        if self.mispkey:
            my_args['mispkey'] = self.mispkey
            logging.info('mispkey as option, value is %s', my_args['mispkey'])
        else:
            my_args['mispkey'] = mispconf.get('mispsetup', 'mispkey')
            logging.debug('misp.conf: mispkey value is %s', my_args['mispkey'])
        if self.sslcheck:
            if self.sslcheck == 'Y' or self.sslcheck == 'y' or self.sslcheck == '1':
                my_args['sslcheck'] = True
            else:
                my_args['sslcheck'] = False                        
            logging.info('sslcheck as option, value is %s', my_args['sslcheck'])
        else:
            my_args['sslcheck'] = mispconf.getboolean('mispsetup', 'sslcheck')
            logging.debug('misp.conf: sslcheck value is %s', my_args['sslcheck'])

        #Search parameters: boolean and filter
        if self.onlyids == 'Y' or self.onlyids == 'y' or self.onlyids == '1':
            my_args['onlyids'] = True
        else:
            my_args['onlyids'] = False
        if self.getuuid == 'Y' or self.getuuid == 'y' or self.getuuid == '1':
            my_args['getuuid'] = True
        else:
            my_args['getuuid'] = False
        if self.getorg == 'Y' or self.getorg == 'y' or self.getorg == '1':
            my_args['getorg'] = True
        else:
            my_args['getorg'] = False
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


# check that ONE of mandatory fields is present
        if self.eventid and self.last:
            logging.error('Options "eventid" and "last" are mutually exclusive')
            raise Exception('Options "eventid" and "last" are mutually exclusive')
        elif self.eventid:
            my_args['eventid'] = self.eventid
            logging.info('Option "eventid" set with %s', my_args['eventid'])
        elif self.last:
            my_args['last'] = self.last
            logging.info('Option "last" set with %s', my_args['last'])
        else:
            logging.error('Missing "eventid" or "last" argument')
            raise Exception('Missing "eventid" or "last" argument')

# path to main components either use default values or set ones
        if mispconf.has_option('mispsetup', 'P3_PATH'):
            _NEW_PYTHON_PATH = mispconf.get('mispsetup', 'P3_PATH')
        else:
            _NEW_PYTHON_PATH = '/usr/bin/python3'
        if mispconf.has_option('mispsetup', 'TMP_PATH'):
            _TMP_PATH = mispconf.get('mispsetup', 'TMP_PATH')
        else:
            _TMP_PATH = '/tmp'

        os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH
        my_process = _SPLUNK_PATH + '/etc/apps/misp42splunk/bin/pymisp_getioc.py'

        # Remove LD_LIBRARY_PATH from the environment (otherwise, we will face some SSL issues
        env = dict(os.environ)
        del env['LD_LIBRARY_PATH']

# use pickle
        config_file = _TMP_PATH + '/mispgetioc_config'
        pickle.dump(my_args, open(config_file, "wb"), protocol=2)
        result_file = _TMP_PATH + '/mispgetioc_result'

        p = subprocess.Popen([_NEW_PYTHON_PATH, my_process, config_file, result_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        (output, stderr) = p.communicate()

        output = {}
        output = pickle.load(open(result_file, "rb"))

        if output:
            for v in output:
                yield v


if __name__ == "__main__":
    # set up logging suitable for splunkd consumption
    logging.root
    logging.root.setLevel(logging.DEBUG)
    dispatch(mispgetioc, sys.argv, sys.stdin, sys.stdout, __name__)
