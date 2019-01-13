
## custom command mispgetioc version 2.0
This custom command must be the first of a search (or a sub-search). The results are displayed in a table that contains:


- always following fields = ['event_id', 'category' 'object_id', 'timestamp', 'to_ids', 'event_tag', 'tags', 'type', 'value']
- if object_id is not equal 0, object attributes are displayed on the same row and field type is set to object, value to object_id
- and a column by type either with a value or empty

So the output can be immediately reused in a search without complex transforms

The command syntax is as follow:

    |mispgetioc ( [eventid=id] | [last=interval]  | date_from="YYYY-mm-dd" (date_to="YYYY-mm-dd") )
                [to_ids=y|n]
                [category="CSV_string"]
                [type="CSV_string"]
                **[pipesplit=y|n]**
                **[getuuid=y|n]**
                **[getorg=y|n**
                **[tags="CSV_string"]**
                **[not_tags="CSV_string"]
                **[getorg=y|n]**
                [misp_url=https://host:port] 
                [misp_key=misp-authorization-key]
                [misp_verifycert=y|n]                 
                
----
    Note: "onlyids" is maintained for compatibility and works like "to_ids"
    Boolean: value can be <1|y|Y|t|true|True|0|n|N|f|false|False>
----
- You must set either parameter 'eventid', 'last' or 'date_from'
    + eventid is the numeric value on the instance. (if you think uuid should be an option introduce an issue or pull request)
    + last interval is a number followed by a letter d(ays), h(ours) or m(inutes)
    + date_from is a date "YYYY-mm-dd" (if date_to is not specify, default is until today)

one example:

    |mispgetioc eventid=477 category="Payload delivery,Network activity,External analysis" type="sha256,domain,ip-dst,text" getuuid=Y getorg=Y

will return the following columns

    | _time | misp_category | misp_event_id | misp_ip_dst | misp_domain | misp_sha256 | misp_orgc | misp_text | misp_to_ids | misp_type | misp_attribute_uuid | misp_value

another example:

    |mispgetioc last=7d type="sha256,domain,ip-dst,text" to_ids=Y getuuid=Y getorg=Y


- The other parameters are optional
    + you may filter the results using
        - to_ids (boolean),
        - [type](https://www.circl.lu/doc/misp/categories-and-types/#types). Use a CSV string to list the types; for example type="domain" or type="domain,hostname,ip-dst"
        - [category](https://www.circl.lu/doc/misp/categories-and-types/#categories) Use a CSV string to list the categories; for example category="Payload delivery" or category="Payload delivery,Network activity,External analysis"
        - tags. Use a CSV string to search for events with these tags
        - not_tags. Use a CSV string to search for events which have not these tags

    + you may set getuuid=Y to get the event UUID in the results 
    + likewise set getorg=Y to list the originating organisation
    + geteventtag will return event tags in the result
    + **if you want to split multivalue attributes set pipesplit to "True" **

- If you need to fecth from another MISP instance different from the default one defined in the setup of the app, you may overwrite the misp server parameters for this search by setting
    + misp_url: set the url to the MISP instance
    + misp_key: misp-authorization-key for this instance
    + misp_verifycert: you may check ssl certificate (default no)  
