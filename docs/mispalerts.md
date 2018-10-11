
# Alerts to interact with MISP
## Create MISP event(s)    
When you create an alert, you may add an alert action to directly create events in MISP based on search results.
This version of the app supports MISP objects. Upgrade MISP and PyMISP accordingly.

### collect results in Splunk
You may search and prepare the results as a table with the following command
```
| rename field1 AS misp_attribute_name (prefix misp_ is removed & '_' are replaced by '-' )
| rename field2 AS fo_object_attribute_name (for file objects)
| rename field3 AS eo_object_attribute_name (for email objects)
| rename field4 AS no_object_attribute_name (for network connection objects)
| table _time to_ids eventkey info category misp\_* fo\_* eo\_* no\_* (etc.)
```
CAUTION:
- Splunk syntax does not like field names containing '-'.
-  Do not forget to check the [object attribute names](https://github.com/MISP/misp-objects/)

* Optional fields:
    - _time: the timestamp will be converted to YYYY-MM-DD for event date. if not provided, set to localtime
    - to_ids: if not defined, set to False
    - category: if not defined, set to None and populated in relation with the type of attribute
    - eventkey: This string/id is used to group several rows of the results belonging to the same event (e.g. attributes of type email-src, email-subject). The actual value is not pushed to MISP. If not specified by row, this value might be overall defined for the alert - see below
    - info: This string will be set in the Info field of MISP event. This value might be overall defined for the alert - see below



### create the alert and add alert_action to create events
Save your search as alert. Select "Alert to create MISP event(s)" as action
Fill in the form to tune your alert to your needs.

* Alert overall description: this section is for Splunk documentation
    - Title: The title of this alert.
    - Description: The description to send with the alert.
* Global event parameters: the parameters will apply for all events created by this alert unless overwritten (see above)
    - Unique ID: indicate the field containing the unique id to group several rows under a single event. If not defined an default eventkey will be generated and all results will be added to the same event.
    - Info: This string will be set in the Info field of MISP event. If not defined, the Info field will contain 'malspam'. By default, it takes a copy of the description (token $description$)
    - Distribution: Change the Distribution. Defaults to Your organisation only
    - Threat Level: Change the Threat Level. Defaults to Undefined
    - Analysis: Change Analysis status. Default to Initial
    - TLP: Change the TLP of the created alert. Defaults to TLP-Amber
    - tags: comma-separated list of tags (not implemented yet)
* Specific alert parameters for MISP serve: If specified, URL and auth key will superseede the config file (misp.conf)
Using those fields you may search in one MISP instance and create events in another one.
    - URL: MISP URL (leave blank to use default settings).
    - Auth Key: The Authkey to submit alerts to (leave blank to use default settings).
    - sslcheck boolean

## Alert for sighting

### search results with one field for timestamp (recommended)
Build your search with as many fields as you want. One field should contain a valid timestamp.

### create the alert and add alert_action for sighting
Save your search as alert. Select "Alert for sighting MISP attribute(s)" as action
Fill in the form to tune your alert to your needs.

* Global event parameters: the parameters will apply for all events created by this alert unless overwritten (see above)
    - Unique ID: indicate the field containing timestamps. If not defined, defaults is now()
    - mode; indicate if sighting is by __value__ or __by attribute uuid__
    - type; indicate if sighting type is
        * Sighting type 0, the default sighting type using the default STIX interpretation of a sighting.
        * Sighting type 1, a false-positive sighting which means this sighting has been interpreted as a false-positive by the organisation.
        * Sighting type 2, an expiration sighting which defines when the sighted attributes is to be expired.

* Specific alert parameters for MISP serve: If specified, URL and auth key will superseede the config file (misp.conf)
Using those fields you may search in one MISP instance and create events in another one.
    - URL: MISP URL (leave blank to use default settings).
    - Auth Key: The Authkey to submit alerts to (leave blank to use default settings).
    - sslcheck boolean
