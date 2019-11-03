# mispgetevent
## custom command mispgetevent version 3.1
This custom command must be the first of a search (or a sub-search). The results are displayed in a table that contains:

- always following fields = ['misp_event_id', 'misp_orgc_id', 'misp_event_date', 'threat_level_id', 'misp_event_info', 'misp_event_published', 'misp_event_uuid', 'misp_attribute_count', 'misp_analysis', 'misp_timestamp', 'misp_distribution', 'misp_publish_timestamp', 'misp_sharing_group_id', 'misp_extends_uuid', 'misp_orgc_name', 'misp_orgc_uuid', 'misp_tag', 'misp_attribute_count' ]
- if object_id is not equal 0, object attributes are displayed on the same row and field type is set to object, value to object_id
- with getioc, attributes are also displayed like for mispgetioc

So the output can be immediately reused in a search without complex transforms

The command syntax is as follow:

    |mispgetevent **[misp_instance=instance_name] ( [json_request=@JSON] [eventid=id] | [last=interval]  | [date="YYYY-mm-dd"] )**
                [page=int]
                [limit=int]
                [category="CSV_string"]
                [type="CSV_string"]
                [tags="CSV_string"]
                [not_tags="CSV_string"]
                [pipesplit=bool]
- **In version >= 3.0.0, you musp provide misp_instance name**
- You must set either parameter 'json_request' 'eventid', 'last' or 'date'
    + eventid is either a single value (event_id on the instance, uuid) or a comma-separated list of values. You can mix event_ids and event uuids.
    + last interval is a number followed by a letter d(ays), h(ours) or m(inutes)
    + date is any valid time filter

## examples
one example:

    |mispgetevent misp_instance=default_misp eventid=477 category="Payload delivery,Network activity,External analysis" type="sha256,domain,ip-dst,text"

will return the following columns

    | _time | misp_category | misp_event_id | misp_ip_dst | misp_domain | misp_sha256 | misp_orgc | misp_text | misp_to_ids | misp_type | misp_attribute_uuid | misp_value

another example:

    |mispgetevent misp_instance=default_misp last=7d type="sha256,domain,ip-dst,text" to_ids=Y getuuid=Y getorg=Y

- The other parameters are optional
    + you may filter the results using
        - [type](https://www.circl.lu/doc/misp/categories-and-types/#types). Use a CSV string to list the types; for example type="domain" or type="domain,hostname,ip-dst"
        - [category](https://www.circl.lu/doc/misp/categories-and-types/#categories) Use a CSV string to list the categories; for example category="Payload delivery" or category="Payload delivery,Network activity,External analysis"
        - tags. Use a CSV string to search for events with these tags
        - not_tags. Use a CSV string to search for events which have not these tags

    + **if you want to split multivalue attributes set pipesplit to "True" **


## logging
in the app, you can set the logging level. logs are written to search.log (access via inspect jobs).

#All parameters
** Only one parameter out of json_request, last, eventid, date must be passed **
## specific paramters for mispgetevent
| mispgetevent status | param name | values (example) | description |
| --- | --- | --- | --- |
| mandatory param | misp_instance | | MISP instance parameters as described in local/inputs.conf. |
| optional param | json_request | valid JSON request | the same JSON request as on MISP API |
| optional param | pipesplit | boolean | split multivalue attributes into 2 attributes. |

## all parameters
    # MANDATORY MISP instance for this search
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
    published = Option(
        doc='''
        **Syntax:** **published=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**select only published events (for option from to) .''',
        require=False, validate=validators.Boolean())
    getioc = Option(
        doc='''
        **Syntax:** **getioc=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to return the list of attributes together with the event.''',
        require=False, validate=validators.Boolean())
    pipesplit = Option(
        doc='''
        **Syntax:** **pipesplit=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to split multivalue attributes into 2 attributes.''',
        require=False, validate=validators.Boolean())