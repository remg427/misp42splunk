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

	# If no specific MISP instance defined, get settings from misp.conf
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

	# Get field name containing values for sighting - defined in alert
	defaulttimestamp = str(int(time.time()))
	config_args['timestamp'] = config.get('unique', defaulttimestamp)

	# Get mode set in alert settings; either byvalue or byuuid
	config_args['mode'] = config.get('mode', 'byvalue')
	
	print >> sys.stderr, "check config_args: %s" % config_args

	# iterate through each row, cleaning multivalue fields and then 
	#	mode byvalue: adding the values under same timestamp
	#	mode byuuid:  adding attribute uuid(s) under same timestamp
	# this builds the dict sightings
	sightings = {}
	for row in results:
	
		# Splunk makes a bunch of dumb empty multivalue fields - we filter those out here 
		row = {key: value for key, value in row.iteritems() if not key.startswith("__mv_")}

		# Get the timestamp as string to group values and remove from row
		timestamp = config_args['timestamp']
		if timestamp in row:
			timestamp = str(row.pop(timestamp))
		else:
			timestamp = defaulttimestamp

		# check if building sighting has been initiated
		# if yes simply add attribute entry otherwise collect other metadata
		if timestamp in sightings:
			values = sightings[timestamp]
		else:
			values = []

		# now we take remaining KV pairs on the line to add values to list 
		if config_args['mode'] == 'byvalue': 
			for key, value in row.iteritems():
				if value != "":
					print >> sys.stderr, "DEBUG key %s value %s" % (key, value) 
					values.append(str(value))
		else:
			if 'uuid' in row:
				value = row['uuid']
				if value != "":
					values.append(str(value))

		sightings[timestamp] = values

	try:

		# call Python3 script to created event
		
		_SPLUNK_PATH = '/opt/splunk'
		_NEW_PYTHON_PATH = '/usr/bin/python3'
		_SPLUNK_PYTHON_PATH = os.environ['PYTHONPATH']
		os.environ['PYTHONPATH'] = _NEW_PYTHON_PATH
		my_process = _SPLUNK_PATH + '/etc/apps/misp42splunk/bin/pymisp_sighting.py'

		# Remove LD_LIBRARY_PATH from the environment (otherwise, we will face some SSL issues
		env = dict(os.environ)
		del env['LD_LIBRARY_PATH']

		FNULL = open(os.devnull, 'w')
		# iterate in dict events to create events
		for timestamp, values in sightings.items():
			sighting = json.dumps(dict(
				timestamp = int(timestamp),
				values    = values
			))
			print >> sys.stderr, 'Calling pymisp_sighting.py for sighting %s' % (sighting)
			# actually send the request to create the alert; fail gracefully
			p = subprocess.Popen([ _NEW_PYTHON_PATH, my_process, str(config_args), str(sighting) ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=FNULL, env=env)
			output = p.communicate()[0]
			print >> sys.stderr, "output pymisp_sighting: %s" % output


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