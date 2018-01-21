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

import os, sys, subprocess, json, gzip, csv, ConfigParser, time

def store_attribute(t,v,to_ids=False,category=None):
	Attribute = {}
	Attribute['type']     = t
	Attribute['value']    = v
	Attribute['to_ids']   = to_ids
	Attribute['category'] = category
	return Attribute

def create_alert(config, results):
	print >> sys.stderr, "DEBUG Creating alert with config %s" % json.dumps(config)

	# check and complement config
	config_args = {}

	# get the URL we need to connect to MISP
	# this can be passed as params of the alert. Defaults to values set in misp.conf
	# get MISP settings stored in misp.conf
	config_file = '/opt/splunk/etc/apps/misp42splunk/local/misp.conf'
	mispconf = ConfigParser.RawConfigParser()
	mispconf.read(config_file)

	mispurl = config.get('URL')
	mispkey = config.get('authkey')

	# If no specific MISP instances defined, get settings from misp.conf
	if not mispurl or not mispkey:
		config_args['mispsrv'] = mispconf.get('mispsetup','mispsrv') 
		config_args['mispkey'] = mispconf.get('mispsetup','mispkey')
		if mispconf.has_option('mispsetup','sslcheck'):
			config_args['sslcheck'] = mispconf.getboolean('mispsetup','sslcheck')
		else:
			config_args['sslcheck'] = False
	else:
		config_args['mispsrv'] = mispurl 
		config_args['mispkey'] = mispkey
		sslcheck = int(config.get('sslcheck', "0"))
		if sslcheck == 1:
			config_args['sslcheck'] = True
		else:
			config_args['sslcheck'] = False

	# Get string values from alert form
	config_args['eventkey'] = config.get('unique', "oneEvent")
	config_args['info']     = config.get('info',   "notable event")
	config_args['tlp']      = config.get('tlp')
	if 'tags' in config:
		config_args['tags'] = config.get('tags')
	
	# Get numeric values from alert form
	config_args['analysis']     = int(config.get('analysis'))
	config_args['threatlevel']  = int(config.get('threatlevel'))
	config_args['distribution'] = int(config.get('distribution'))
	
	print >> sys.stderr, "DEBUG check config_args: %s" % config_args

	# iterate through each row, cleaning multivalue fields and then adding the attributes under same event key
	# this builds the dict events
	events = {}
	for row in results:
	
		# Splunk makes a bunch of dumb empty multivalue fields - we filter those out here 
		row = {key: value for key, value in row.iteritems() if not key.startswith("__mv_")}

		# GEt the specific eventkey if define in Splunk search. Defaults to alert form got above
		eventkey = config_args['eventkey']
		if eventkey in row:
			eventkey = row.pop(eventkey)

		# check if building event has been initiated
		# if yes simply add attribute entry otherwise collect other metadata
		# remove fields _time and info from row and keep their values if this is a new event
		if eventkey in events:
			event = events[eventkey]
			artifacts = event['attribute']
			if '_time' in row:
				remove = str(row.pop('_time'))
			if 'info' in row:
				remove = row.pop('info')
		else:
			event = {}
			artifacts = []
			if '_time' in row:
				event['timestamp'] = str(row.pop('_time'))
			else:
				event['timestamp'] = str(int(time.time()))
			if 'info' in row:
				event['info'] = row.pop('info')
			else:
				event['info'] = config_args['info']

		# collect attribute value and build type=value entry
		if 'to_ids' in row:
			if str(row.pop('to_ids')) == 'True':
				to_ids == True
			else:
				to_ids = False
		else:
			to_ids = False
		
		if 'category' in row:
			category = str(row.pop('category'))
		else:
			category = None

		if 'type' in row and 'value' in row:
			artifacts.append(store_attribute(str(row.pop('type')),str(row.pop('value')),to_ids,category))
		elif 'type' in row or 'value' in row:
			print >> sys.stderr, "FATAL fields type and value MUST be present together"
			sys.exit(4)
		else:
		# now we take remaining KV pairs to add to dict 
			for key, value in row.iteritems():
				if value != "":
					print >> sys.stderr, "DEBUG key %s value %s" % (key, value)
					artifacts.append(store_attribute(str(key).replace('_','-'),str(value),to_ids,category))

		event['attribute'] = artifacts
		
		events[eventkey] = event
	

	try:

		# call Python3 script to created event
		
		_SPLUNK_PATH = '/opt/splunk'
		_NEW_PYTHON_PATH = '/usr/bin/python3'
		_SPLUNK_PYTHON_PATH = os.environ['PYTHONPATH']
		os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH
		my_process = _SPLUNK_PATH + '/etc/apps/misp42splunk/bin/pymisp_create_event.py'

		# Remove LD_LIBRARY_PATH from the environment (otherwise, we will face some SSL issues
		env = dict(os.environ)
		del env['LD_LIBRARY_PATH']

		FNULL = open(os.devnull, 'w')
		# iterate in dict events to create events
		for key, event in events.items():
			print >> sys.stderr, 'DEBUG Calling pymisp_create_event.py for event %s' % event
			# actually send the request to create the alert; fail gracefully
			p = subprocess.Popen([ _NEW_PYTHON_PATH, my_process, str(config_args), str(event) ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=FNULL, env=env)

	# somehow we got a bad response code from thehive
	# some other request error occurred
	except IOError as e:
		print >> sys.stderr, "ERROR Error creating alert: %s" % e
		
	
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
			# file exists - try to open it; fail gracefully
			try:
				# open the file with gzip lib, start making alerts
				# can with statements fail gracefully??
				with gzip.open(filepath) as file:
					# DictReader lets us grab the first row as a header row and other lines will read as a dict mapping the header to the value
					# instead of reading the first line with a regular csv reader and zipping the dict manually later
					# at least, in theory
					reader = csv.DictReader(file)
					# make the alert with predefined function; fail gracefully
					create_alert(configuration, reader)
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