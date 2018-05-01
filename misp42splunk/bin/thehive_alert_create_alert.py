#!/usr/bin/env python
# Generate TheHive alerts
#
# Author: Remi Seguy <remg427@gmail.com>
#
# Copyright: LGPLv3 (https://www.gnu.org/licenses/lgpl-3.0.txt)
# Feel free to use the code, but please share the changes you've made

# most of the code here was based on the following example on splunk custom alert actions
# http://docs.splunk.com/Documentation/Splunk/6.5.3/AdvancedDev/ModAlertsAdvancedExample

import os, sys, json, gzip, csv, requests, ConfigParser, time
from requests.auth import HTTPBasicAuth

def create_alert(config, results):
	print >> sys.stderr, "DEBUG Creating alert with config %s" % config

	# check and complement config

	# get the URL we need to connect to TheHive API
	# this can be passed as params of the alert. Defaults to values set in misp.conf
	# get TheHive settings stored in misp.conf

	config_file = '/opt/splunk/etc/apps/misp42splunk/local/misp.conf'
	thehiveconf = ConfigParser.RawConfigParser()
	thehiveconf.read(config_file)

	if ( 'thehiveURL' in config and 'thehiveKey' in config ):
		url  = config.get('thehiveURL')
		auth = config.get('thehiveKey')
		if url in [None, ''] or auth in [None, '']:
			print >> sys.stderr, "FATAL TheHive URL and auth key were set in alert defintion but one is empty: URL %s -  Key %s " % (url,auth)
			sys.exit(5)
	elif (thehiveconf.has_option('mispsetup','thehiveURL') and 
	      thehiveconf.has_option('mispsetup','thehiveKey') ) :		
		url  = thehiveconf.get('mispsetup','thehiveURL')
		auth = thehiveconf.get('mispsetup','thehiveKey')
	else:
		print >> sys.stderr, "FATAL TheHive API URL and/or API KEY missing (should be in misp.conf or in alert definition" 
		sys.exit(4)

	# get the URL and API KEY we need

	# iterate through each row, cleaning multivalue fields and then adding the attributes under same alert key
	# this builds the dict alerts
	# https://github.com/TheHive-Project/TheHiveDocs/tree/master/api

	alerts = {}
	alertRef = 'SPK' + str(int(time.time()))

	for row in results:
	
		# Splunk makes a bunch of dumb empty multivalue fields - we filter those out here 
		row = {key: value for key, value in row.iteritems() if not key.startswith("__mv_")}

		# find the field name used for a unique identifier and strip it from the row
		if 'unique' in config:
			id = config.get('unique')
			sourceRef = str(row.pop(id)) # grabs that field's value and assigns it to our sourceRef 
		else:
			sourceRef = alertRef

		# check if attributes have been stored for this sourceRef. If yes, retrieve them to add new ones from this row
		if sourceRef in alerts:
			alert = alerts[sourceRef]
			attributes = alert["attributes"]
		else:
			alert = {}
			attributes = {} 

		# attributes can be provided in two ways
		# - either a table with columns type and value
		# - or a table with one column per type and value in the cell (it can be empty for some rows)
		# 
		# they are collected and added to the dict in the format data:dataType
		# using data as key avoids duplicate entries if some field values are common to several rows with the same sourceRef!
		
		# check if row has columns type and value
		if 'type' in row and 'value' in row:
			mykey   = str(row.pop('type'))
			myvalue = str(row.pop('value'))
			if myvalue != "":
				print >> sys.stderr, "DEBUG key %s value %s" % (mykey, myvalue) 
				attributes[myvalue] = mykey
				# now we take the others KV pairs if any to add to dict 
				for key, value in row.iteritems():
					if value != "":
						print >> sys.stderr, "DEBUG key %s value %s" % (key, value) 
						attributes[str(value)] = key
		
		# if there is one column per type in results
		else:
		# now we take those KV pairs to add to dict 
			for key, value in row.iteritems():
				if value != "":
					print >> sys.stderr, "DEBUG key %s value %s" % (key, value) 
					attributes[str(value)] = key
	
		if attributes:
			alert['attributes'] = attributes
			alerts[sourceRef] = alert

	# actually send the request to create the alert; fail gracefully
	try:

		# iterate in dict alerts to create alerts
		for srcRef, attributes in alerts.items():
			print >> sys.stderr, "DEBUG sourceRef is %s and attributes are %s" % (srcRef, attributes)

			artifacts = []

			# now we take those KV pairs and make a list-type of dicts 
			for value, dType in attributes['attributes'].items():
				artifacts.append(dict(
					dataType = dType,
					data = value,
					message = "%s observed in this alert" % dType
				))

			#prepare payload for alert creation
			myDescription = config.get('description', "No description provided.")
			if myDescription in [None, '']:
				myDescription = "No description provided."
			myType = config.get('type', "alert")
			if myType in [None, '']:
				myType = "alert"
			mySource = 	config.get('source', "splunk")
			if mySource in [None, '']:
				mySource = "splunk"
			myTemplate = config.get('caseTemplate', "default")
			if myTemplate in [None, '']:
				myTemplate = "default"

			payload = json.dumps(dict(
				title = config.get('title'),
				description = myDescription,
				tags = [] if config.get('tags') is None else config.get('tags').split(","), # capable of continuing if Tags is empty and avoids split failing on empty list
				severity = int(config.get('severity', 2)),
				tlp = int(config.get('tlp', -1)),
				type = myType,
				artifacts = artifacts,
				source = mySource,
				caseTemplate = myTemplate,
				sourceRef = srcRef # I like to use eval id=md5(_raw) 
			))

			# set proper headers
			headers = {'Content-type': 'application/json'}
			headers['Authorization'] = 'Bearer ' + auth

			print >> sys.stderr, 'DEBUG Calling url="%s" with headers %s and payload=%s' % (url, headers, payload) 
			# post alert
			response = requests.post(url, headers=headers, data=payload, verify=False)
			print >> sys.stderr, "INFO theHive server responded with HTTP status %s" % response.status_code
			# check if status is anything other than 200; throw an exception if it is
			response.raise_for_status()
			# response is 200 by this point or we would have thrown an exception
			print >> sys.stderr, "DEBUG theHive server response: %s" % response.json()
	
	# somehow we got a bad response code from thehive
	except requests.exceptions.HTTPError as e:
		print >> sys.stderr, "ERROR theHive server returned following error: %s" % e
	# some other request error occurred
	except requests.exceptions.RequestException as e:
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
