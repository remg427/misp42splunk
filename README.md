# misp42splunk
**A Splunk app to use MISP as a backend (lookup, alerts to create or update events)**
If you have TheHive installed, you also may create alerts.

In short, you can:
1. easily configure the app from Splunk GUI; no need to edit files via the console.
2. get IOC from MISP instance in search command line: __| mispgetioc__
3. alert action to send alerts to TheHive:
    - results may have one column per artifact type or,
    - results must have at least 2 columns named **type** (of artifacts) and **value**
4. **alert action to create events in MISP**
    - results must have at least 2 columns named **type** (of attributes) and **value**
    - or results may have one column per artifact type folowing MISP attribute names; in this case you can use **_** instead of **-** as Splunk does not like so much field name with a -; for example use **ip_src**, the script will replace it by **ip-src**.    
5. alert action to increment attributes sighting in MISP:
    - likewise you may select in alert settings if sighting is by value or by uuid; both modes work with timestamps.

# Prerequisites
1. Install Python 3 on the Splunk Search Head.
2. Install PyMISP (see https://github.com/MISP/PyMISP).
3. Check that your Splunk SH can connect to the MISP instance. 
4. In App setup screen, you can adapt pathes to python3 binary and temp folder

# Installation
This app is designed to run on Splunk Search Head(s) on Linux plateforms
1. Download this [file](misp42splunk.tar.gz) which is the Splunk app ( it is an archive containing the sub-directory misp42splunk)
3. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file"
4. A custom endpoint has been defined so you need to restart Splunk (for later updates, you may skip this step)
5. At next logon, you should be invited to configure the app (if not go to Manage Apps > App-MISP42 > Set up) 
    - For MISP
        - provide the url to your MISP instance;
        - provide the authkey;
        - check (or not) the certificate of the MISP server.
    - For TheHive
        - provide the url to the API of your instance;
        - provide the authkey.
    - Pathes to python3 binary and temp folder

# Use Cases

Here some activities you may carry out more easily with this app.
## Hunting in Splunk logs
Fresh IOC from MISP > saved searches in Splunk > on match create an alert on [TheHive](https://thehive-project.org/) or (later) any SIR platform of your choice.

## Creating events based on automated sandboxing
If you have output of analysis pushed to Splunk you may automate the creation of events
Log on sandboxing output > saved search to qualify, sanitize (dedup remove top Alexa, etc.) and prepare the table (misp_*, fo_*, eo_* etc.) > set a splunk alert to create event(s) in MISP
* Only fields prefixed with misp_ (or fo_ for file objects, eo_ for email objects) are imported
* if you use MISP objects, please upgrade PyMISP and MISP accordingly
* Advise: for objects verify the name of the fields to be created; for example see [Email Object definition](https://github.com/MISP/misp-objects/blob/a5c331038edcbb86557396cf39508f0e3e35a33b/objects/email/definition.json)

## Sighting in MISP based on Splunk alerts
Search for attributes values/uuids in Splunk > alert to increment sighting counters (standard,false positive,expiration) in MISP for those values/uuids 

# Usage
## custom command [mispgetioc](docs/mispgetioc.md)
## Alerts to [create TheHive alerts](docs/thehivealerts.md)
## Alert to [update MISP](docs/mispalerts.md)
### Alert to create MISP event(s)
### Alert for attribute sighting in MISP

# Todo
- [X] implement event tagging in misp_alert_create_event
- [ ] store some saved searches and lookups as examples

# Credits
The creation of this app started from work done by https://github.com/xme/splunk/tree/master/getmispioc and the associated blog https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/ for MISP interactions.

The alert_action for TheHive is inpired by [this Splunk app](https://splunkbase.splunk.com/app/3642/)

# Licence
This app misp42splunk is licensed under the GNU Lesser General Public License v3.0.
