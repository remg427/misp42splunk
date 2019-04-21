# mispgetioc
## custom command mispgetioc version 3.0
This custom command must be the first of a search (or a sub-search). The results are displayed in a table that contains:

- always following fields = ['event_id', 'category' 'object_id', 'timestamp', 'to_ids', 'event_tag', 'tags', 'type', 'value']
- if object_id is not equal 0, object attributes are displayed on the same row and field type is set to object, value to object_id
- and a column by type either with a value or empty

So the output can be immediately reused in a search without complex transforms

The command syntax is as follow:

    |mispgetioc **[misp_instance=instance_name] ( [eventid=id] | [last=interval]  | date_from="YYYY-mm-dd" (date_to="YYYY-mm-dd") )**
                [to_ids=bool]
                [published=bool]
                [category="CSV_string"]
                [type="CSV_string"]
                [tags="CSV_string"]
                [not_tags="CSV_string"]
                [threat_level=1-4]
                [limit=int]
                [pipesplit=bool]
                [getuuid=bool]
                [add_description=bool]
                [geteventtag=bool]
                [getorg=bool]
                [add_description=bool]
                [warning_list=bool]
----
    Note: Boolean can be <1|y|Y|t|true|True|0|n|N|f|false|False>
----
- **In version >= 3.0.0, you musp provide misp_instance name**
- You must set either parameter 'eventid', 'last' or 'date_from'
    + eventid is either a single value (event_id on the instance, uuid) or a comma-separated list of values. You can mix event_ids and event uuids.
    + last interval is a number followed by a letter d(ays), h(ours) or m(inutes)
    + date_from is a date "YYYY-mm-dd" (if date_to is not specify, default is until today)

## examples
one example:

    |mispgetioc misp_instance=default_misp eventid=477 category="Payload delivery,Network activity,External analysis" type="sha256,domain,ip-dst,text" getuuid=Y getorg=Y

will return the following columns

    | _time | misp_category | misp_event_id | misp_ip_dst | misp_domain | misp_sha256 | misp_orgc | misp_text | misp_to_ids | misp_type | misp_attribute_uuid | misp_value

another example:

    |mispgetioc misp_instance=default_misp last=7d type="sha256,domain,ip-dst,text" to_ids=Y getuuid=Y getorg=Y

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


## logging
in the app, you can set the logging level. logs are written to search.log (access via inspect jobs).


## all parameters
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described in local/inputs.conf.''',
        require=True)
    # MANDATORY: eventid XOR last
    eventid         = Option(
        doc = '''
        **Syntax:** **eventid=***id1(,id2,...)*
        **Description:**list of event ID(s). **eventid**, **last** and **date_from** are mutually exclusive''',
        require=False, validate=validators.Match("eventid",r"^[0-9a-f,\-]+$"))
    last            = Option(
        doc = '''
        **Syntax:** **last=***<int>d|h|m*
        **Description:**publication duration in day(s), hour(s) or minute(s). **eventid**, **last** and **date_from** are mutually exclusive''',
        require=False, validate=validators.Match("last",r"^[0-9]+[hdm]$"))
    date_from       = Option(
        doc = '''
        **Syntax:** **date_from=***date_string"*
        **Description:**starting date. **eventid**, **last** and **date_from** are mutually exclusive''',
        require=False)
    date_to         = Option(
        doc = '''
        **Syntax:** **date_to=***date_string"*
        **Description:**(optional)ending date in searches with date_from. if not set default is now''',
        require=False)
    to_ids          = Option(
        doc = '''
        **Syntax:** **to_ids=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to search only attributes with the flag "to_ids" set to true.''',
        require=False, validate=validators.Boolean())
    published       = Option(
        doc = '''
        **Syntax:** **published=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**select only published events (for option from to) .''',
        require=False, validate=validators.Boolean())
    category        = Option(
        doc = '''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    type            = Option(
        doc = '''
        **Syntax:** **type=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    tags            = Option(
        doc = '''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for. Wildcard is %.''',
        require=False)
    not_tags        = Option(
        doc = '''
        **Syntax:** **not_tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to exclude from results. Wildcard is %.''',
        require=False)
    threat_level_id = Option(
        doc = '''
        **Syntax:** **threat_level=***<int>*
        **Description:**define the threat_level_id''',
        require=False, validate=validators.Match("threat_level_id", r"^[1-4]$"))
    limit         = Option(
        doc = '''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search; default 10000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    getuuid         = Option(
        doc = '''
        **Syntax:** **getuuid=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return attribute UUID.''',
        require=False, validate=validators.Boolean())
    getorg          = Option(
        doc = '''
        **Syntax:** **getorg=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return the ID of the organisation that created the event.''',
        require=False, validate=validators.Boolean())
    geteventtag     = Option(
        doc = '''
        **Syntax:** **geteventtag=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return also event tag(s). By default only attribute tag(s) are returned.''',
        require=False, validate=validators.Boolean())
    pipesplit     = Option(
        doc = '''
        **Syntax:** **pipesplit=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to split multivalue attributes into 2 attributes.''',
        require=False, validate=validators.Boolean())
    add_description = Option(
        doc = '''
        **Syntax:** **add_description=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return misp_description.''',
        require=False, validate=validators.Boolean())
    warning_list = Option(
        doc = '''
        **Syntax:** **warning_list=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to filter out well known values.''',
        require=False, validate=validators.Boolean())
