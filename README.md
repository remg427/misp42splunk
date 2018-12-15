# overview
misp42splunk app connects [MISP](http://www.misp-project.org/) and [Splunk](www.splunk.com).
The app is designed to be easy to install, set up and maintain using the Splunk GUI without directly editing files.
You can use **as many MISP instances as you like;** one being defined at setup time to be the default instance.

The main use cases are:
1. MISP to SPLUNK:
	- **| mispgetioc _params_ | ...** gets MISP event attributes into Splunk search pipeline: 
	- **search ... |mispsearch field=myvalue | ...** searches for matching attributes in MISP: 
	- **search ...|mispsight field=myvalue | ...** gets sighting information for a specific value (note that if there is FP, only first hit is returned)
2. MISP for SPLUNK: 2 Splunk alert actions are available to directly create events or increment attribute sighting in a MISP instance. 

# Installation
This app is designed to run on Splunk Search Head(s) on Linux plateforms (not tested on Windows but it could work)
1. Download this [file](misp42splunk.tar.gz) which is the Splunk app ( it is an archive containing the sub-directory misp42splunk)
3. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file"
4. A custom endpoint has been defined so you need to restart Splunk (for later updates, you may skip this step)
5. At next logon, you should be invited to configure the app (if not go to Manage Apps > App-MISP42 > Set up) 
    - provide the url to your MISP instance;
    - provide the authkey;
    - check (or not) the certificate of the MISP server.

# Use Cases

## Hunting in Splunk logs
Fresh IOC from MISP > saved searches in Splunk 

## Creating events based on automated sandboxing
If you have output of analysis pushed to Splunk you may automate the creation of events
Log on sandboxing output > saved search to qualify, sanitize (dedup remove top Alexa, etc.) and prepare the table (misp_*, fo_*, eo_* and no_*) > set a splunk alert to create event(s) in MISP
* Only fields prefixed with misp_ (or fo_ for file objects, eo_ for email objects) are imported
* if you use MISP objects, please upgrade PyMISP and MISP accordingly
* Advise: for objects, verify the name of the fields to be created [Object definitions](https://github.com/MISP/misp-objects/tree/master/objects)

## Sighting in MISP based on Splunk alerts
Search for attributes values/uuids in Splunk > alert to increment sighting counters (standard,false positive,expiration) in MISP for those values/uuids 

# Usage
- custom commands
    * [mispgetioc](docs/mispgetioc.md) reporting command
    * [mispsearch](docs/mispsearch.md) streaming command
    * [mispsight](docs/mispsight.md) streaming command
- Splunk alert actions to [update MISP](docs/mispalerts.md)
    *  Alert to create MISP event(s)
    *  Alert for attribute sighting in MISP

# Todo
- [X] implement event tagging in misp_alert_create_event
- [X] store some saved searches and lookups as examples
- [X] remove dependency for pymisp and python3

# Credits
The creation of this app started from work done by https://github.com/xme/splunk/tree/master/getmispioc and the associated blog https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/ for MISP interactions.

# Licence
This app misp42splunk is licensed under the GNU Lesser General Public License v3.0.
