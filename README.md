# misp42splunk
A Splunk app to use MISP as a backend (lookup and store events)

# Credits
This app is largely inspired by https://github.com/xme/splunk/tree/master/getmispioc and the associated blog https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/

# Prerequisites
1. Install Python 3 on the Splunk Search Head.
2. Check that python3 is at /usr/bin/python3.

    + if not, you may create a symbolic link to the python3.x binary.
    + alternatively you may edit misp42splunk/bin/misp-get-ioc.py and adjust the path to your environment.

3. Install PyMISP (see https://github.com/CIRCL/PyMISP).
4. Check that your Splunk SH can connect to the MISP instance. 

# Installation
This App is meant for Splunk Search heads
1. Download the ZIP file and install the app on your Splunk Search Head(s) (you may remove -master from file name)
    * Please note that this app come with a copy of Splunk SDK under misp42splunk/bin
2. A custom endpoint has been defined so you need to restart Splunk (for later updates, you may skip this step)
3. At next logon, you should be invited to configure the app (if not go to Manage Apps > TA-MISP 42 Spliunk > Set up) 

    - provide the url to your MISP instance;
    - provide the authkey;
    - [not implemented] check the certificate of the MISP server.

# Usage

## mispgetioc
This custom command must be the first of a search (or a sub-search). The results are displayed in a table.
The command syntax is as follow:

    |mispgetioc ( [eventid=id] | [last=interval] )
                [onlyids=y|n]
                [category=string]
                [type=string]
                [server=https://host:port] 
                [authkey=misp-authorization-key]
                [sslcheck=y|n]                  

- You must set either eventid or last parameters
- last interval is a number followed by d(ays), h(ours) or m(inutes)
- you may filter the results using type and category parameters
- you may overwrite the misp server parameters for this search

## Alert to create MISP event(s)    
When you create an alert, you may add an alert action to create events based on search results

### collect results in Splunk
At the moment you need to search and prepare the results as a table with the following command
    | table _time type value to_ids eventkey info category

* Mandatory fields:
    - _time: the timestamp will be converted to YYYY-MM-DD for event date
    - type: the type of attribute. It must use MISP attribute names
    - value: the value of the attribute - you should check that the value complies with the type

* Optional fields:
    - to_ids: if not defined, set to False
    - category: if not defined, set to None and populated in relation with the type of attribute
    - eventkey: This string/id is used to group several rows of the results belonging to the same event (e.g. attributes of type email-src, email-subject). The actual value is not pushed to MISP. If not specified by row, this value might be overall defined for the alert - see below
    - info: This string will be set in the Info field of MISP event. This value might be overall defined for the alert - see below

### create the alert and add alert_action to create events
Save your search as alert. Select "Alert to create MISP event(s)" as action
Fill in the form to tune your alert to your needs.

=> Alert overall description: this section is for Splunk documentation
=> Global event parameters: the parameters will apply for all events created by this alert unless overwritten (see above)
    - Unique ID: define the default eventkey. if not defined an default eventkey will be generated and all results will be added to the same event.
    - Info: This string will be set in the Info field of MISP event. If not defined, the Info field will contain 'malspam'
    - Distribution:
    - Threat Level:
    - Analysis:
    - TLP: (not implemented yet)
    - tags: comma-separated list of tags (not implemented yet)
=> MISP server parameters: If specified, URL and auth key will superseede the config file (misp.conf)

# Todo
- implement sslcheck boolean. Always set to False for mispgetioc (it works for alert_action)
- implement event tagging (TLP, etc.) in misp_alert_create_event
- store some saved searches and lookups as examples

# Licence
This app misp42splunk is licensed under the GNU Lesser General Public License v3.0
