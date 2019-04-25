# Overview
misp42splunk app connects [MISP](http://www.misp-project.org/) and [Splunk](www.splunk.com).

The app is designed to be easy to install, set up and maintain using the Splunk GUI.

MISP instances must be version 2.4.98 or above (new REST API).

**misp42splunk version >=3.0.0**: this is a major update; after installation, restart splunk, launch the app and create one misp instance under inputs. It is recommended to name it default_misp. If you need **several instances**, create additional inputs.

# Usage

1. MISP to SPLUNK:

    - **| mispgetioc misp_instance=default_misp _params_ | ...** gets MISP event attributes into Splunk search pipeline. 
    - **| mispapireport misp_instance=default_misp _params_ | ...** gets MISP event attributes into Splunk search pipeline. 
	- **search ... |mispsearch misp_instance=default_misp field=myvalue | ...** searches for matching attributes in MISP.
	- **search ... |mispsight  misp_instance=default_misp field=myvalue | ...** gets sighting information for a specific value (note that if there is FP, only first hit is returned)

2. MISP for SPLUNK: 2 Splunk alert actions are available
        
	- one action to create new events or **edit** existing ones if you provide an eventid (or UUID). This allows to contribute to misp event(s) across several alert triggers.
	- one action to increment attribute sighting in a MISP instance. 


# Installation
This app is designed to run on **Splunk Search Head(s)** on Linux plateforms (not tested on Windows but it could work)

1. **working with master** Download this [file](misp42splunk.tar.gz) which is the Splunk app
1. **working with other branches** Download the ZIP file and extract the folder misp42splunk which actually contains the Splunk app. You have to compress that folder as misp42splunk.tar.gz
3. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file"
5. At next logon, you should be invited to configure the app (if not go to Manage Apps > misp42 > launch app)
6. create at least one input for example "default_misp" 
    - provide the url to your MISP instance;
    - provide the authkey;
    - check (or not) the certificate of the MISP server.
    - use (or not) the proxy for this instance
    - provide client certificate if required (and check the box to use it)

# Use Cases

## Hunting in Splunk logs
Fresh IOC from MISP > saved searches in Splunk 

## Creating (or editing) events based on automated sandboxing
If you have output of analysis pushed to Splunk you may automate the creation of events
Log on sandboxing output > saved search to qualify, sanitize (dedup remove top Alexa, etc.) and prepare the table (misp_*, fo_*, eo_* and no_*) > set a splunk alert to create event(s) in MISP
* Only fields prefixed with misp_ (or fo_ for file objects, eo_ for email objects, no_ for network objects) are imported
* Advise: for objects, verify the name of the fields to be created [Object definitions](https://github.com/MISP/misp-objects/tree/master/objects)
* If you provide an eventid, that event is updated with attributes and objects instead of creating a new one. **WARNING** apparently the **API does create duplicate objects** if you submit sevral time the same inputs.

## Sighting in MISP based on Splunk alerts
Search for attributes values/uuids in Splunk > alert to increment sighting counters (standard,false positive,expiration) in MISP for those values/uuids 

# Usage
- custom commands
    * [mispgetioc](docs/mispgetioc.md) reporting command
    * [mispapireport](docs/mispapireport.md) reporting command (it is a wrapper of MISP API less customised as mispgetioc)
    * [mispsearch](docs/mispsearch.md) streaming command
    * [mispsight](docs/mispsight.md) streaming command
- Splunk alert actions to [update MISP](docs/mispalerts.md)
    *  Alert to create MISP event(s)
    *  Alert for attribute sighting in MISP

# Saved searches and Enterprise Security App
Several saved searches are provided to easily create KV store lookups which can be used later. THe default behaviour is to append new event attributes to the KV store but you may switch to replace it.
Based on those searches, you can easily created local CSV files and feed intel to Enterprise Security App.

# todo
   - [ ] savedsearches to pull intel for domain ip and email address (for Enterprise Security)
   - [ ] dashboard to see IOC available/pulled from MISP
   
# Credits
The creation of this app started from work done by https://github.com/xme/splunk/tree/master/getmispioc and the associated blog https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/ for MISP interactions.

# Licence
This app misp42splunk is licensed under the GNU Lesser General Public License v3.0.
