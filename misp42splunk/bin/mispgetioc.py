#!/usr/bin/env python
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
import os, sys, subprocess, ConfigParser
import cPickle as pickle
from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators

@Configuration(requires_preop=False)

class mispgetioc(ReportingCommand):
    mispsrv         = Option(require=False, validate=validators.Match("mispsrv",     r"^https?:\/\/[0-9a-zA-Z\.]+(?:\:\d+)?$"))
    mispkey         = Option(require=False, validate=validators.Match("mispkey",     r"^[0-9a-zA-Z]{40}$"))
    sslcheck        = Option(require=False, validate=validators.Match("sslcheck",    r"^[yYnN01]$"))
    eventid         = Option(require=False, validate=validators.Match("eventid",     r"^[0-9]+$"))
    last            = Option(require=False, validate=validators.Match("last",        r"^[0-9]+[hdwm]$"))
    onlyids         = Option(require=False, validate=validators.Match("onlyids",     r"^[yYnN01]+$"))
    getuuid         = Option(require=False, validate=validators.Match("getuuid",     r"^[yYnN01]+$"))
    getorg          = Option(require=False, validate=validators.Match("getorg",      r"^[yYnN01]+$"))
    category        = Option(require=False)
    type            = Option(require=False)
    tags            = Option(require=False)
    not_tags            = Option(require=False)

    @Configuration()

    def map(self, records):
        self.logger.debug('mispgetioc.map')
        yield {}
        return

    def reduce(self, records):
        self.logger.debug('mispgetioc.reduce')
        if self.sslcheck == None:
            self.sslcheck = 'n'

        _SPLUNK_PATH = os.environ['SPLUNK_HOME']

        # open misp.conf
        config_file = _SPLUNK_PATH + '/etc/apps/misp42splunk/local/misp.conf'
        mispconf = ConfigParser.RawConfigParser()
        mispconf.read(config_file)

        # Generate args
        my_args = {}
        #MISP instance parameters        
        if self.mispsrv:
            my_args['mispsrv'] = self.mispsrv
        else:
            my_args['mispsrv'] = mispconf.get('mispsetup','mispsrv')
        if self.mispkey:
            my_args['mispkey'] = self.mispkey
        else:
            my_args['mispkey'] = mispconf.get('mispsetup','mispkey')
        if self.sslcheck:
            if self.sslcheck == 'Y' or self.sslcheck == 'y' or self.sslcheck == '1':
                my_args['sslcheck'] = True
            else:
                my_args['sslcheck'] = False                        
        else:
            my_args['sslcheck'] = mispconf.getboolean('mispsetup','sslcheck')

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
        if self.category != None:
            my_args['category'] = self.category
        else:
            my_args['category'] = None
        if self.type != None:
            my_args['type'] = self.type
        else:
            my_args['type'] = None
        if self.tags != None:
            my_args['tags'] = self.tags
        else:
            my_args['tags'] = None
        if self.not_tags != None:
            my_args['not_tags'] = self.not_tags
        else:
            my_args['not_tags'] = None


#check that ONE of mandatory fields is present
        if self.eventid and self.last:
            print('DEBUG Options "eventid" and "last" are mutually exclusive')
            exit(2)
        elif self.eventid:
            my_args['eventid'] = self.eventid
        elif self.last:
            my_args['last'] = self.last
        else:
            print('DEBUG Missing "eventid" or "last" argument')
            exit(1)

#path to main components either use default values or set ones
        if mispconf.has_option('mispsetup','P3_PATH'):
            _NEW_PYTHON_PATH = mispconf.get('mispsetup','P3_PATH')
        else:
            _NEW_PYTHON_PATH = '/usr/bin/python3'
        if mispconf.has_option('mispsetup','TMP_PATH'):
            _TMP_PATH = mispconf.get('mispsetup','TMP_PATH')
        else:
            _TMP_PATH = '/tmp'
            
        _SPLUNK_PYTHON_PATH = os.environ['PYTHONPATH']
        os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH
        my_process = _SPLUNK_PATH + '/etc/apps/misp42splunk/bin/pymisp_getioc.py'

        # Remove LD_LIBRARY_PATH from the environment (otherwise, we will face some SSL issues
        env = dict(os.environ)
        del env['LD_LIBRARY_PATH']

        FNULL = open(os.devnull, 'w')

#use pickle
        swap_file = _TMP_PATH + '/mispgetioc_config'
        pickle.dump(my_args, open(swap_file, "wb"), protocol=2)

        p = subprocess.Popen([ _NEW_PYTHON_PATH, my_process, swap_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        stdout, stderr  = p.communicate()

        if stderr:
            print('DEBUG error in pymisp_getioc.py')
            exit(1)                    

        results = {}
        output = pickle.load(open(swap_file, "rb"))

        for v in output:
            yield v                              

if __name__ == "__main__":
    dispatch(mispgetioc, sys.argv, sys.stdin, sys.stdout, __name__)
