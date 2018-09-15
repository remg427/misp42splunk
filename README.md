# misp42splunk
misp42splunk app connects [MISP](http://www.misp-project.org/) and [Splunk](www.splunk.com). The app is designed to be easy to install, set up and maintain using the Splunk GUI without editing directly files. You can use **as many MISP instances as you like;** one being defined at setup time to be the default instance.

The main use cases are:
1. MISP to  SPLUNK: get MISP event attributes into Splunk search pipeline: **| mispgetioc _params_ | ...**. see 
2. MISP for SPLUNK: 2 Splunk alert actions are available to directly create events or increment attribute sighting in a MISP instance. 

BONUS: You can also create Splunk alert action to create [The Hive](https://thehive-project.org/) alerts

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
#### custom command [mispgetioc](docs/mispgetioc.md)
#### Splunk alert actions to [update MISP](docs/mispalerts.md)
##### -- Alert to create MISP event(s)
##### -- Alert for attribute sighting in MISP
#### Splunk alerts to [create TheHive alerts](docs/thehivealerts.md)

# Todo
- [X] implement event tagging in misp_alert_create_event
- [ ] store some saved searches and lookups as examples

# Credits
The creation of this app started from work done by https://github.com/xme/splunk/tree/master/getmispioc and the associated blog https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/ for MISP interactions.

The alert_action for TheHive is inpired by [this Splunk app](https://splunkbase.splunk.com/app/3642/)

# Licence
This app misp42splunk is licensed under the GNU Lesser General Public License v3.0.
