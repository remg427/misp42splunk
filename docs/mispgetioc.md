
## custom command mispgetioc version 2.0
This custom command must be the first of a search (or a sub-search). The results are displayed in a table that contains:

    + always following fields = ['event_id','timestamp', 'type', 'category', 'to_ids', 'value']
    + and a column by types either with a value or empty

So the output can be immediately reused in a search without complex transforms

The command syntax is as follow:

    |mispgetioc ( [eventid=id] | [last=interval] )
                [onlyids=y|n]
                [category=CSV_string]
                [type=CSV_string]
                **[getuuid=y|n|Y|N|0|1]**
                **[getorg=y|n|Y|N|0|1]**
                [server=https://host:port] 
                [authkey=misp-authorization-key]
                [sslcheck=y|n]                  
                

- You must set either parameter 'eventid' or 'last'
    + eventid is the numeric value on the instance. (if you think uuid should be an option intoduce an issue or pull request)
    + last interval is a number followed by a letter d(ays), h(ours) or m(inutes)

one example:

    |mispgetioc eventid=477 category="Payload delivery,Network activity,External analysis" type="sha256,domain,ip-dst,text" getuuid=Y getorg=Y

will return the following columns

    | _time | category | event_id | ip-dst | misp_domain | misp_sha256 | orgc | text | to_ids | type | uuid | value

another example:

    |mispgetioc last=7d type="sha256,domain,ip-dst,text" onlyids=Y getuuid=Y getorg=Y

IMPORTANT: on big result sets, you may get an error "EOFError at "/opt/splunk/etc/apps/misp42splunk/bin/mispgetioc.py", line 137 : ". The module pickle is overloaded. try with smaller period or with filters.

- The other parameters are optional
    + you may filter the results using
        - onlyids (boolean),
        - [type](https://www.circl.lu/doc/misp/categories-and-types/#types). Use a CSV string to list the types; for example type="domain" or type="domain,hostname,ip-dst"
        - [category](https://www.circl.lu/doc/misp/categories-and-types/#categories) Use a CSV string to list the categories; for example category="Payload delivery" or category="Payload delivery,Network activity,External analysis"

    + you may set getuuid=Y to get the event uuid in the results 
    + likewise set getorg=Y to list the originating organisation

- If you need to fecth from another MISP instance different from the default one defined in the setup of the app, you may overwrite the misp server parameters for this search by setting
    + server: set the url to the MISP instance
    + authkey: misp-authorization-key for this instance
    + sslcheck: you may check ssl certificate (default no)  