#!/usr/bin/env python
#
# Create Events in MISP from results of alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made
#
# most of the code here was based on the following example on splunk custom alert actions
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample

import os
import sys
import subprocess
import json
import tempfile
import ConfigParser
import time
import pickle

__author__     = "Remi Seguy"
__license__    = "LGPLv3"
__version__    = "3.0.0"
__maintainer__ = "Remi Seguy"
__email__      = "remg427@gmail.com"


def create_alert(config, filename):
    print >> sys.stderr, "DEBUG Creating alert with config %s" % json.dumps(config)

    # get the misp_url we need to connect to MISP
    # this can be passed as params of the alert. Defaults to values set in misp.conf
    # get MISP settings stored in misp.conf
    _SPLUNK_PATH = os.environ['SPLUNK_HOME']

    # open misp.conf
    config_file = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'local' + os.sep + 'misp.conf'
    mispconf = ConfigParser.RawConfigParser()
    mispconf.read(config_file)

    # check and complement config
    config_args = {}

    # MISP instance parameters
    misp_url = config.get('misp_url')
    misp_key = config.get('misp_key')

    # If no specific MISP instances defined, get settings from misp.conf
    if misp_url and misp_key:
        config_args['misp_url'] = misp_url
        config_args['misp_key'] = misp_key
        misp_verifycert = int(config.get('misp_verifycert', "0"))
        if misp_verifycert == 1:
            config_args['misp_verifycert'] = True
        else:
            config_args['misp_verifycert'] = False
    else:
        config_args['misp_url'] = mispconf.get('mispsetup', 'misp_url')
        config_args['misp_key'] = mispconf.get('mispsetup', 'misp_key')
        if mispconf.has_option('mispsetup','misp_verifycert'):
            config_args['misp_verifycert'] = mispconf.getboolean('mispsetup', 'misp_verifycert')
        else:
            config_args['misp_verifycert'] = False

    # Get string values from alert form
    config_args['eventkey'] = config.get('unique', "oneEvent")
    config_args['info'] = config.get('info', "notable event")
    config_args['tlp'] = config.get('tlp')
    if 'tags' in config:
        config_args['tags'] = config.get('tags')
    else:
        config_args['tags'] = None

    # Get numeric values from alert form
    config_args['analysis']     = int(config.get('analysis'))
    config_args['threatlevel']  = int(config.get('threatlevel'))
    config_args['distribution'] = int(config.get('distribution'))

    # add filename of the file containing the result of the search
    config_args['filename'] = filename

    try:

        # path to main components either use default values or set ones
        if mispconf.has_option('mispsetup', 'P3_PATH'):
            _NEW_PYTHON_PATH = mispconf.get('mispsetup', 'P3_PATH')
        else:
            _NEW_PYTHON_PATH = '/usr/bin/python3'

        os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH

        env = dict(os.environ)
        del env['LD_LIBRARY_PATH']

        my_process = _SPLUNK_PATH + os.sep + 'etc' + os.sep + 'apps' + os.sep + 'misp42splunk' + os.sep + 'bin' + os.sep + 'pymisp_create_event.py'
        # Remove LD_LIBRARY_PATH from the environment (otherwise, we will face some SSL issues

        # use pickle
        _TMP_PATH = tempfile.mkdtemp()
        config_file = _TMP_PATH + '/misp42_alert_create'
        pickle.dump(config_args, open(config_file, "wb"), protocol=2)

        print >> sys.stderr, "DEBUG env: %s" % env
        try:
            p = subprocess.Popen([_NEW_PYTHON_PATH, my_process, config_file],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
            output, err = p.communicate()
            rc = p.returncode
            print >> sys.stderr, "INFO returncode %s" % str(rc)
            if rc != 0:
                print >> sys.stderr, "error in pymisp_create_event.py. error_code %s" % str(rc)
        except Exception:
            print >> sys.stderr, "subprocess failed"
    # somehow we got a bad response code from thehive
    # some other request error occurred
    except IOError as e:
        print >> sys.stderr, "preparing call of pymisp_create_event.py: %s" % e


if __name__ == "__main__":
    # make sure we have the right number of arguments - more than 1; and first argument is "--execute"
    if len(sys.argv) > 1 and sys.argv[1] == "--execute":
        # read the payload from stdin as a json string
        payload = json.loads(sys.stdin.read())
        # extract the file path and alert config from the payload
        configuration = payload.get('configuration')
        filepath = payload.get('results_file')

        # test if the results file exists - this should basically never fail unless we are parsing configuration incorrectly
        # example path this variable should hold: '/opt/splunk/var/run/splunk/12938718293123.121/results.csv.gz'
        if os.path.exists(filepath):
            # file exists - try to open and if successful add path to configuration
            try:
                # open the file with gzip lib, start making alerts
                # can with statements fail gracefully??
                # configuration['filepath'] = filepath
                # DictReader lets us grab the first row as a header row and other lines will read as a dict mapping the header to the value
                # instead of reading the first line with a regular csv reader and zipping the dict manually later
                # at least, in theory
                create_alert(configuration, filepath)
                # by this point - all alerts should have been created with all necessary observables attached to each one
                # we can gracefully exit now
                sys.exit(0)
            # something went wrong with opening the results file
            except IOError as e:
                print >> sys.stderr, "FATAL Results file exists but could not be opened/read"
                sys.exit(3)
        # somehow the results file does not exist
        else:
            print >> sys.stderr, "FATAL Results file does not exist"
            sys.exit(2)
    # somehow we received the wrong number of arguments
    else:
        print >> sys.stderr, "FATAL Unsupported execution mode (expected --execute flag)"
        sys.exit(1)