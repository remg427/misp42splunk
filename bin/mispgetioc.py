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
from splunklib.searchcommands import dispatch, ReportingCommand, Configuration, Option, validators

@Configuration(requires_preop=False)

class mispgetioc(ReportingCommand):
        mispsrv         = Option(require=False, validate=validators.Match("mispsrv",    r"^https?:\/\/[0-9a-zA-Z\.]+(?:\:\d+)?$"))
        mispkey         = Option(require=False, validate=validators.Match("mispkey",    r"^[0-9a-zA-Z]{40}$"))
        sslcheck        = Option(require=False, validate=validators.Match("sslcheck",   r"^[yYnN01]$"))
        eventid         = Option(require=False, validate=validators.Match("eventid",    r"^[0-9]+$"))
        last            = Option(require=False, validate=validators.Match("last",       r"^[0-9]+[hdwm]$"))
        onlyids         = Option(require=False, validate=validators.Match("onlyids",    r"^[yYnN01]+$"))
        category        = Option(require=False)
        type            = Option(require=False)

        @Configuration()

        def map(self, records):
                self.logger.debug('mispgetioc.map')
                yield {}
                return

        def reduce(self, records):
                self.logger.debug('mispgetioc.reduce')
                if self.sslcheck == None:
                        self.sslcheck = 'n'

                # open misp.conf
                config_file = '/opt/splunk/etc/apps/misp42splunk/local/misp.conf'
                config = ConfigParser.RawConfigParser()
                config.read(config_file)

                # Generate args
                my_args = {}
                if self.mispsrv:
                        my_args['mispsrv'] = self.mispsrv
                else:
                        my_args['mispsrv'] = config.get('mispsetup','mispsrv')
                if self.mispkey:
                        my_args['mispkey'] = self.mispkey
                else:
                        my_args['mispkey'] = config.get('mispsetup','mispkey')
                if self.sslcheck:
                        my_args['sslcheck'] = self.sslcheck
                else:
                        my_args['sslcheck'] = config.getboolean('mispsetup','sslcheck')

                if self.onlyids == 'Y' or self.onlyids == 'y' or self.onlyids == '1':
                        onlyids = True
                else:
                        onlyids = False

                if self.eventid and self.last:
                        print('Options "eventid" and "last" are mutually exclusive')
                        exit(1)

                if self.eventid:
                       my_args['eventid'] = self.eventid
                elif self.last:
                        my_args['last'] = self.last
                else:
                        print('Missing "eventid" or "last" argument')
                        exit(1)

                _SPLUNK_PATH = '/opt/splunk'
                _NEW_PYTHON_PATH = '/usr/bin/python3'
                _SPLUNK_PYTHON_PATH = os.environ['PYTHONPATH']
                os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH
                my_process = _SPLUNK_PATH + '/etc/apps/misp42splunk/bin/misp-get-ioc.py'

                # Remove LD_LIBRARY_PATH from the environment (otherwise, we will face some SSL issues
                env = dict(os.environ)
                del env['LD_LIBRARY_PATH']

                FNULL = open(os.devnull, 'w')
                p = subprocess.Popen([ _NEW_PYTHON_PATH, my_process, str(my_args) ],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=FNULL, env=env)
                output = p.communicate()[0]
                results = {}
                for v in eval(output):
                        # Do not display deleted attributes
                        if v['deleted'] == False:
                                # If specified, do not display attributes with the non-ids flag set to False
                                if onlyids == True and v['to_ids'] == False:
                                        continue
                                if self.category != None and self.category != v['category']:
                                        continue
                                if self.type != None and self.type != v['type']:
                                        continue
                                results['value']        = v['value']
                                results['category']     = v['category']
                                results['type']         = v['type']
                                results['to_ids']       = str(v['to_ids'])
                                yield results
if __name__ == "__main__":
    dispatch(mispgetioc, sys.argv, sys.stdin, sys.stdout, __name__)