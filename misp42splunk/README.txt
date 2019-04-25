This is an add-on powered by the Splunk Add-on Builder.

misp42splunk app connects MISP and Splunk.

The app is designed to be easy to install, set up and maintain using the Splunk GUI without directly editing files.
MISP instances must be version 2.4.97 or above (new REST API).

The main use cases are:
1. MISP to SPLUNK:
| mispgetioc params | ... gets MISP event attributes into Splunk search pipeline.
| mispapireport params | ... gets MISP event attributes into Splunk search pipeline.
search ... |mispsearch field=myvalue | ... searches for matching attributes in MISP.
search ... |mispsight field=myvalue | ... gets sighting information for a specific value (note that if there is FP, only first hit is returned)

2. MISP for SPLUNK: 2 Splunk alert actions are available
- one action to create or edit events. NEW in > 2.0.14, if you provide an eventid (or UUID), then this event is edited instead of creating a new one. This allows to contribute to misp event(s) across several alert triggers.
- one action to increment attribute sighting in a MISP instance.


see more on https://github.com/remg427/misp42splunk
