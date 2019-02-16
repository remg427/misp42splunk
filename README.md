# Overview
misp42splunk app connects [MISP](http://www.misp-project.org/) and [Splunk](www.splunk.com).

The app is designed to be easy to install, set up and maintain using the Splunk GUI without directly editing files.

MISP instances must be version 2.4.98 or above (new REST API).

**misp42splunk version >=2.1.3**: if the filter "to_ids" is used, only matching attributes of objects are returned. it could result into partial data.

## Several MISP instances
As before, you can use **as many MISP instances as you like!** and now with version >= 2.1.0, this is easy to manage/use.

  1. Install and configure the app via the setup screen. Provide all information for the default MISP instance
  2. When saving, the file local/misp.conf is updated to reflect your changes
  3. NEW: the changes are written to another file lookups/misp_instances.csv (created if it does not exist)
  4. You can then edit that lookup table to add additional instances, one per row 

        | misp_instance | misp_url | misp_key | misp_verifycert | misp_use_proxy | description |
        |---------------|----------|----------|-----------------|----------------|-------------|
        | default | url1 | key1 | False | False | default MISP instance defined at MISP42 app setup |
        | mispdev | url2 | key2 | True | True | MISP sandbox |

  5. If you want to use another insatnce than default one simply add:  misp_instance=instance_name

# Usage

1. MISP to SPLUNK:

	- **| mispgetioc _params_ | ...** gets MISP event attributes into Splunk search pipeline. 
    - **| mispapireport _params_ | ...** gets MISP event attributes into Splunk search pipeline. 
	- **search ... |mispsearch field=myvalue | ...** searches for matching attributes in MISP.
	- **search ... |mispsight  field=myvalue | ...** gets sighting information for a specific value (note that if there is FP, only first hit is returned)

2. MISP for SPLUNK: 2 Splunk alert actions are available
        
	- one action to create or **edit** events. NEW in > 2.0.14, if you provide an eventid (or UUID), then this event is edited instead of creating a new one. This allows to contribute to misp event(s) across several alert triggers.
	- one action to increment attribute sighting in a MISP instance. 


# Installation
This app is designed to run on **Splunk Search Head(s)** on Linux plateforms (not tested on Windows but it could work)

1. **working with master** Download this [file](misp42splunk.tar.gz) which is the Splunk app ( it is an archive containing the sub-directory misp42splunk)
1. **working with other branches** Download the ZIP file and extract the folder misp42splunk which actually contains the Splunk app. You have to compress that folder as misp42splunk.tar.gz
3. Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file"
4. A custom endpoint has been defined so you need to restart Splunk (for later updates, you may skip this step)
5. At next logon, you should be invited to configure the app (if not go to Manage Apps > App-MISP42 > Set up) 
    - provide the url to your MISP instance;
    - provide the authkey;
    - check (or not) the certificate of the MISP server.
    - use (or not) the proxy for this instance
    - define a proxy if required (leave blank for no proxy)

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
    * [mispsearch](docs/mispsearch.md) streaming command
    * [mispsight](docs/mispsight.md) streaming command
- Splunk alert actions to [update MISP](docs/mispalerts.md)
    *  Alert to create MISP event(s)
    *  Alert for attribute sighting in MISP

# Saved searches and Enterprise Security App
Several saved searches are provided to easily create KV store lookups which can be used later. THe default behaviour is to append new event attributes to the KV store but you may switch to replace it.
Based on those searches, you can easily created local CSV files and feed intel to Enterprise Security App.

# developer's corner
switch to v3.0 branch where a MISP API wrapper under development 
    | mispapireport

# Credits
The creation of this app started from work done by https://github.com/xme/splunk/tree/master/getmispioc and the associated blog https://blog.rootshell.be/2017/10/31/splunk-custom-search-command-searching-misp-iocs/ for MISP interactions.

# Licence
This app misp42splunk is licensed under the GNU Lesser General Public License v3.0.
