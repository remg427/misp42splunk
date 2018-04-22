# Alert sent to TheHive
When you create a Splunk alert, you may add an alert action to create alerts in TheHive
## collect results in Splunk
### search results with a column by artifact type
you may build a search returning some values for these fields

    autonomous-system
    domain
    file
    filename
    fqdn
    hash
    ip
    mail
    mail_subject
    other
    regexp
    registry
    uri_path
    url
    user-agent

and one field to group rows.
For example

    | eval id = md5(some common key in rows belonging to the same alert)
    | table id, autonomous-system, domain, file, filename, fqdn, hash, ip, mail, mail_subject, other, regexp, registry, uri_path, url, user-agent

Values may be empty for some fields; they will be dropped gracefully. You may add any other columns, they will be passed as elements but only fields above are imported as observables when you create/update a case.

### search results with 2 columns: type & value
You may also build a search with one artifact by row. You may use field id to group several rows together    
For example: 

    | mispgetioc last=1d
    | eval id = md5(eventid)
    | table id, type, value


## create the alert action "Alert to create THEHIVE alert(s)"
Fill in fields. If value is not provided, default will be provided if needed.

* Alert overall description
    - Case Template: The case template to use for imported alerts.
    - Type: The alert type. Defaults to "alert".
    - Source: The alert source. Defaults to "splunk".
    - Unique ID: A field name that contains a unique identifier specific to the source event. You may use the field value to group artifacts under the same alert.
    - Title: The title to use for created alerts.
    - Description: The description to send with the alert.
    - Tags: Use single comma-separated string without quotes for multiple tags (ex. "badIP,spam").
    - Severity: Change the severity of the created alert.
    - TLP: Change the TLP of the created alert. Default is TLP:AMBER
* TheHive API parameters (optional if they have been defined in general setup)
    - URL: The URL to submit alerts to e.g. http://hive.example.com/api/alert.
    - API KEY: The API KEY for authentication