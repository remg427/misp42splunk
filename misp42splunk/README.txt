This is an add-on powered by the Splunk Add-on Builder.

misp42splunk app connects MISP and Splunk.

Usage

    MISP to SPLUNK (custom commands):
    | mispgetioc misp_instance=default_misp _params_ | ... gets MISP event attributes into Splunk search pipeline.
    | mispgetevent misp_instance=default_misp _params_ | ... gets MISP events into Splunk search pipeline using direct calls of the API.
    search ... |mispsearch misp_instance=default_misp field=myvalue | ... searches for matching attributes in MISP.
    search ... |mispsight misp_instance=default_misp field=myvalue | ... gets sighting information for a specific value (note that if there is FP, only first hit is returned) ** IMPORTANT ** mispapireport has been replaced by mispgetioc (use json_request=)

    MISP for SPLUNK: 2 Splunk alert actions are available

    one action to create new events or edit existing ones if you provide an eventid (or UUID). This allows to contribute to misp event(s) across several alert triggers.
    one action to increment attribute sighting in a MISP instance.

Installation

This app is designed to run on Splunk Search Head(s) on Linux plateforms (not tested on Windows but it could work)

    working with master Download this file which is the Splunk app
    working with other branches Download the ZIP file and extract the folder misp42splunk which actually contains the Splunk app. You have to compress that folder as misp42splunk.tar.gz
    Install the app on your Splunk Search Head(s): "Manage Apps" -> "Install app from file"
    At next logon, you should be invited to configure the app (if not go to Manage Apps > misp42 > launch app)
    create at least one input for example "default_misp". Please note that mandatory fields "intervals" and "index" are not used. Just put a valid value
        provide a name for example default_misp to follow the examples provided in this doc
        provide the url to your MISP instance (version > 2.4.117)
        provide the authkey,
        check (or not) the certificate of the MISP server,
        use (or not) the proxy for this instance,
        provide client certificate if required (and check the box to use it) inputs
    If you need several instances, create additional inputs.
    Important: Role(s)/user(s) using this app must have the capability to "list_storage_passwords" (as API KEYs and proxy password(s) are safely stored encrypted )

Use Cases
Build a dashboard

You may get fresh attributes from a MISP instance and save them under an index (for example index=misp). Then a dashboard can be build by using this template. The result should be similar to this video Thanks to @ran2 for sharing!
Hunting in Splunk logs

Fresh IOC from MISP > saved searches in Splunk
Creating (or editing) events based on automated sandboxing

If you have output of analysis pushed to Splunk you may automate the creation of events Log on sandboxing output > saved search to qualify, sanitize (dedup remove top Alexa, etc.) and prepare the table (misp_, fo_, eo_* and no_*) > set a splunk alert to create event(s) in MISP

    Only fields prefixed with misp_ (or fo_ for file objects, eo_ for email objects, no_ for network objects) are imported
    Advise: for objects, verify the name of the fields to be created Object definitions
    If you provide an eventid, that event is updated with attributes and objects instead of creating a new one. WARNING apparently the API does create duplicate objects if you submit sevral time the same inputs.

Sighting in MISP based on Splunk alerts

Search for attributes values/uuids in Splunk > alert to increment sighting counters (standard,false positive,expiration) in MISP for those values/uuids
Saved searches and Enterprise Security App

Several saved searches are provided to easily create KV store lookups which can be used later. The default behaviour is to append new event attributes to the KV store but you may switch to replace it. Based on those searches, you can easily created local CSV files and feed intel to Enterprise Security App.
you can also use this example (thanks @xg-simon for sharing):

| mispgetioc misp_instance=default_misp pipesplit=true  add_description=true category="External analysis,Financial fraud,Internal reference,Network activity,Other,Payload delivery,Payload installation,Payload type,Persistence mechanism,Person,Social network,Support Tool,Targeting data" last=90d to_ids=true geteventtag=true warning_list=true not_tags="osint:source-type=\"block-or-filter-list\""
| eval ip=coalesce(misp_ip_dst, misp_ip_src,misp_ip)
| eval domain=misp_domain
| eval src_user=coalesce(misp_email_src, misp_email_src_display_name)
| eval subject=misp_email_subject
| eval file_name=misp_filename
| eval file_hash=coalesce(misp_sha1, misp_sha256, misp_sha512, misp_md5, misp_ssdeep)
| eval url=coalesce(misp_url,misp_hostname)
| eval http_user_agent=misp_user_agent
| eval registry_value_name=misp_regkey
| eval registry_value_text=if(isnotnull(misp_regkey),misp_value,null)
| eval description = misp_description
| table domain,description,file_hash,file_name,http_user_agent,ip,registry_value_name,registry_value_text,src_user,subject,url,weight

Usage

    custom commands
        mispgetioc reporting command levaring /attributes/restSearch endpoint
        mispgetevent reporting command levaring /events/restSearch endpoint
        mispsearch streaming command
        mispsight streaming command
    Splunk alert actions to update MISP
        Alert to create MISP event(s)
        Alert for attribute sighting in MISP.

This app misp42splunk is licensed under the GNU Lesser General Public License v3.0.

see more on https://github.com/remg427/misp42splunk
