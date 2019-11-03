# mispgetioc
## custom command mispgetioc version 3.1
This custom command must be the first of a search (or a sub-search). The results are displayed in a table that contains:

- always following fields = ['misp_attribute_id', 'misp_category', 'misp_event_id', 'misp_event_uuid', 'misp_object_id', 'misp_timestamp', 'misp_to_ids', 'event_tag', 'misp_tag', 'misp_type', 'misp_value'  ]
- if object_id is not equal 0, object attributes are displayed on the same row and field type is set to object, value to object_id
- depending on options, 'misp_attribute_uuid' (getuuid is True), 'misp_orgc_id' (getorg is True), 'misp_event_info' and 'misp_description' (add_descriptioon is True)
- and a column by type either with a value or empty

So the output can be immediately reused in a search without complex transforms

The command syntax is as follow:

    |mispgetioc **[misp_instance=instance_name] ( [json_request=@JSON] [eventid=id] | [last=interval]  | [date="YYYY-mm-dd"] )**
                [page=int]
                [limit=int]
                [to_ids=bool]
                [category="CSV_string"]
                [type="CSV_string"]
                [tags="CSV_string"]
                [not_tags="CSV_string"]
                [threat_level=1-4]
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
- You must set either parameter 'json_request' 'eventid', 'last' or 'date'
    + eventid is either a single value (event_id on the instance, uuid) or a comma-separated list of values. You can mix event_ids and event uuids.
    + last interval is a number followed by a letter d(ays), h(ours) or m(inutes)
    + date is any valid time filter

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

#All parameters
** Only one parameter out of json_request, last, eventid, date must be passed **
## specific paramters for mispgetioc
| mispgetioc status | param name | values (example) | description |
| --- | --- | --- | --- |
| mandatory param | misp_instance | | MISP instance parameters as described in local/inputs.conf. |
| optional param | json_request | valid JSON request | the same JSON request as on MISP API |
| optional param | getuuid | boolean | returns attribute uuid |
| optional param | getorg | boolean | Boolean to return the ID of the organisation that created the event |
| optional param | pipesplit | boolean | split multivalue attributes into 2 attributes. |
| optional param | add_description | boolean | return misp_description. | 


## All parameters for /attributes/searchRest and equivalent param names
| Key | Status | mispgetioc status | param name | values (example) | description |
| --- |  --- | --- | --- | --- | --- |
| "returnFormat" | "mandatory" | forced to JSON | | | |
| "page" | "optional" | optional param | page | integer (1) | works only with limit |
| "limit" | "optional" | optional param | limit | integer (0,1000,...) | if not provided set to 1000 |
| "value" | "optional" | not managed | | | |
| "type" | "optional" | optional param | type | CSV string (domain  or domain,domain|ip etc.) | type of attributes - for combined use pipesplit boolean |
| "category" | "optional" | optional param | category | CSV string | attributes categories |
| "org" | "optional" | not managed | | | |
| "tags" | "optional" | optional param | tags and not_tags | CSV strings | values passed to tags are combined (OR) and to not_tags NOT (OR) |
| "date" | "optional" | optional param | date | any valid time related filters (7d or "[\"14d\",\"7d\"]") | this applies to the user set date field on events |
| "last" | "optional" | optional param | last | integer followed by d (for days), h (for hours) or m (for minutes) | applies to the publish_timestamp |
| "publish_timestamp" | "optional" | optional param | last | see above | publish_timestamp is used instead of last (alias) |
| "eventid" | "optional" | optional param | eventid | | |
| "withAttachments" | "optional" | forced to False | | | |
| "uuid" | "optional" | not managed | | | |
| "timestamp" | "optional" | not managed | | | |
| "enforceWarninglist" | "optional" | optional param | warning_list | boolean | |
| "to_ids" | "optional" | optional param | to_ids | boolean | if set to True and warning_list not set then enforceWarninglist set to True |
| "deleted" | "optional" | forced to False | | | |
| "includeEventUuid" | "optional" | forced to True | | | |
| "includeEventTags" | "optional" | optional param | gettags | boolean | |
| "event_timestamp" | "optional" | not managed | | | |
| "threat_level_id" | "optional" | optional param | threat_level_id | 1,2,3 or 4 | define the threat_level_id |
| "eventinfo" | "optional" | not managed | | | |
| "includeProposals" | "optional" | not managed | | | |
| "includeDecayScore" | "optional" | not managed | | | |
| "includeFullModel" | "optional" | not managed | | | |
| "decayingModel" | "optional" | not managed | | | |
| "excludeDecayed" | "optional" |  not managed | | | |
| "score" | "optional" | not managed | | | |

## all parameters
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as described in local/inputs.conf.''',
        require=True)
    # MANDATORY: json_request XOR eventid XOR last XOR date
    json_request=Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False)    
    eventid = Option(
        doc='''
        **Syntax:** **eventid=***id1(,id2,...)*
        **Description:**list of event ID(s) or event UUID(s).''',
        require=False, validate=validators.Match("eventid", r"^[0-9a-f,\-]+$"))
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:** publication duration in day(s), hour(s) or minute(s).
        **nota bene:** last is an alias of published_timestamp''',
        require=False, validate=validators.Match("last", r"^[0-9]+[hdm]$"))
    date = Option(
        doc='''
        **Syntax:** **date=***The user set event date field - any of valid time related filters"*
        **Description:**starting date. **eventid**, **last** and **date** are mutually exclusive''',
        require=False)
    # Other params
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search; default 1000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    type = Option(
        doc='''
        **Syntax:** **type=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    category = Option(
        doc='''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for. Wildcard is %.''',
        require=False)
    tags = Option(
        doc='''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for. Wildcard is %.''',
        require=False)
    not_tags = Option(
        doc='''
        **Syntax:** **not_tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to exclude from results. Wildcard is %.''',
        require=False)
    warning_list = Option(
        doc='''
        **Syntax:** **warning_list=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to filter out well known values.''',
        require=False, validate=validators.Boolean())
    to_ids = Option(
        doc='''
        **Syntax:** **to_ids=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to search only attributes with the flag "to_ids" set to true.''',
        require=False, validate=validators.Boolean())
    geteventtag = Option(
        doc='''
        **Syntax:** **geteventtag=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean includeEventTags. By default only attribute tag(s) are returned.''',
        require=False, validate=validators.Boolean())
    threat_level_id = Option(
        doc='''
        **Syntax:** **threat_level=***<int>*
        **Description:**define the threat_level_id criterion''',
        require=False, validate=validators.Match("threat_level_id", r"^[1-4]$"))
    getuuid = Option(
        doc='''
        **Syntax:** **getuuid=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return attribute UUID.''',
        require=False, validate=validators.Boolean())
    getorg = Option(
        doc='''
        **Syntax:** **getorg=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return the ID of the organisation that created the event.''',
        require=False, validate=validators.Boolean())
    pipesplit = Option(
        doc='''
        **Syntax:** **pipesplit=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to split multivalue attributes into 2 attributes.''',
        require=False, validate=validators.Boolean())
    add_description = Option(
        doc='''
        **Syntax:** **add_description=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return misp_description.''',
        require=False, validate=validators.Boolean())
