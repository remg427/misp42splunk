# custom command mispcollect

This custom command is a wrapper to call the MISP API endpoint /attributes/restSearch or /events/restSearch and return results as events with field mapping
## [mispcollect-command]
syntax = |mispcollect <mispcollect-options> 
shortdesc = retrieve attributes or events in misp instance. Must provide either option "eventid", "last", "date_from" or "json_request".
description = mispcollect pulls attributes or events from misp instance and display as events.\
  You can filter on "category" or "type" of attributes, on attributes having the 'to_ids' flag\
  or specific "tags" or "not_tags".\
  You may display the attribute uuid (getuuid: default = false) or creating org (getorg: default=false)
usage = public
example1 = | mispcollect misp_instance=test last=10d
comment1 = retrieve attributes of all events published in last 10 days and display as events
example2 = | mispcollect last=10d endpoint=events
comment2 = retrieve events published in last 10 days and display as events.

# All params
    ## MANDATORY MISP instance for this search
    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:** MISP instance parameters
        as described in local/misp42splunk_instances.conf.''',
        require=True)
    # MANDATORY: json_request XOR eventid XOR last XOR date
    json_request = Option(
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
        **Syntax:** **date=***The user set event date field
         - any of valid time related filters"*
        **Description:**starting date.
         **eventid**, **last** and **date** are mutually exclusive''',
        require=False)
    ## Other params
    category = Option(
        doc='''
        **Syntax:** **category=***CSV string*
        **Description:**Comma(,)-separated string of categories to search for.
         Wildcard is %.''',
        require=False)
    endpoint = Option(
        doc='''
        **Syntax:** **endpoint=***<events|attributes>*
        **Description:**selection of MISP API restSearch endpoint.
        **default**: /attributes/restSearch''',
        require=False, validate=validators.Match("output", r"(events|attributes)"))
    geteventtag = Option(
        doc='''
        **Syntax:** **geteventtag=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean includeEventTags. By default only
         attribute tag(s) are returned.''',
        require=False, validate=validators.Boolean())
    keep_related = Option(
        doc='''
        **Syntax:** **keep_related=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to keep related events.
        default is to drop  RelatedEvents to reduce volume.''',
        require=False, validate=validators.Boolean())
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search;
         default 1000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    not_tags = Option(
        doc='''
        **Syntax:** **not_tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to exclude.
         Wildcard is %.''',
        require=False)
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    tags = Option(
        doc='''
        **Syntax:** **tags=***CSV string*
        **Description:**Comma(,)-separated string of tags to search for.
         Wildcard is %.''',
        require=False)
    to_ids = Option(
        doc='''
        **Syntax:** **to_ids=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to search only attributes with the flag
         "to_ids" set to true.''',
        require=False, validate=validators.Boolean())
    type = Option(
        doc='''
        **Syntax:** **type=***CSV string*
        **Description:**Comma(,)-separated string of types to search for.
         Wildcard is %.''',
        require=False)
    warning_list = Option(
        doc='''
        **Syntax:** **warning_list=***<1|y|Y|t|true|True|0|n|N|f|false|False>*
        **Description:**Boolean to filter out well known values.''',
        require=False, validate=validators.Boolean())
