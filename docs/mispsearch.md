
## custom command mispsearch
This custom command is a streaming command that applies to each event.
It searches for the value of the field selected in the command.
If there are matches, additional multi-value fields (starting by misp_) are added to the dataset.

The command syntax is as follow:

    search something... | mispsearch field=<field_containing_value_to_search_for> 
                misp_instance=<instance_name>
                [onlyids=y|n]
                [gettag=y|n]
                
**WARNING**: if the field contains null value, you may get a server error 500. You can use the splunk command __|fillnull field__ to avoid those errors (Thanks @jlachesk for solving this #54).
    
one simple example:

    ... | field clientip | mispsearch field=clientip misp_instance=prod | dedup misp_json

another example
    ... | field ip | mispsearch field=ip misp_instance=ops json_request="{\"returnFormat\": \"json\", \"withAttachments\": \"false\", \"includeEventUuid\": \"true\", \"includeEventTags\": \"true\"}"  
    
will add following fields 

    misp_type
    misp_value
    misp_to_ids
    misp_category
    misp_attribute_uuid
    misp_event_id
    misp_tag (if gettag is set to yes)


- The other parameters are optional
    + you may filter the results using
        - onlyids (boolean),
    + you may set gettag=Y to get the attribute tags
    + you may provide a full JSON request body.  returnFormat is forced to 'json' and withAttachments to False

## All params

    misp_instance = Option(
        doc='''
        **Syntax:** **misp_instance=instance_name*
        **Description:**MISP instance parameters as \
        described in local/misp42splunk_instances.conf''',
        require=True)
    field = Option(
        doc='''
        **Syntax:** **field=***<fieldname>*
        **Description:**Name of the field containing \
        the value to search for.''',
        require=True, validate=validators.Fieldname())
    to_ids = Option(
        doc='''
        **Syntax:** **to_ids=***<y|n>*
        **Description:** Boolean to search only attributes with to_ids set''',
        require=False, validate=validators.Boolean())
    includeEventUuid = Option(
        doc='''
        **Syntax:** **includeEventUuid=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to include event UUID(s) to results.''',
        require=False, validate=validators.Boolean())
    includeEventTags = Option(
        doc='''
        **Syntax:** **includeEventTags=***y|Y|1|true|True|n|N|0|false|False*
        **Description:**Boolean to include Event Tags to results.''',
        require=False, validate=validators.Boolean())
    last = Option(
        doc='''
        **Syntax:** **last=***<int>d|h|m*
        **Description:**Publication duration in day(s), hour(s) or minute(s) 
        to limit search scope only to published events in last X timerange.''',
        require=False, validate=validators.Match("last", r"^[0-9]+[hdm]$"))
    limit = Option(
        doc='''
        **Syntax:** **limit=***<int>*
        **Description:**define the limit for each MISP search; \
        default 1000. 0 = no pagination.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    page = Option(
        doc='''
        **Syntax:** **page=***<int>*
        **Description:**define the page for each MISP search; default 1.''',
        require=False, validate=validators.Match("limit", r"^[0-9]+$"))
    json_request = Option(
        doc='''
        **Syntax:** **json_request=***valid JSON request*
        **Description:**Valid JSON request''',
        require=False)