
## custom command mispquery
This custom command is a streaming command that applies to each event.
It searches for the value of the field selected in the command.
If there are matches, additional fields are added to the dataset (starting by misp_) with a CSV string.

The command syntax is as follow:

    search something... | mispquery field=<field_containing_value_to_search_for> 
                [onlyids=y|n]
                [get_comment=y|n]
                [mispsrv=https://host:port] 
                [mispkey=misp-authorization-key]
                [sslcheck=y|n]                 
                

one dummy example:

    ... | field clientip | mispquery field=clientip | dedup misp_json

will add following fields 

    misp_json
    misp_type
    misp_value
    misp_to_ids
    misp_category
    misp_uuid
    misp_event_id
    misp_comment if get_comment was set to Yes

- The other parameters are optional
    + you may filter the results using
        - onlyids (boolean),
    + you may set get_comment=Y to get the attribute comments 

- If you need to fecth from another MISP instance different from the default one defined in the setup of the app, you may overwrite the misp server parameters for this search by setting
    + mispsrv: set the url to the MISP instance
    + mispkey: misp-authorization-key for this instance
    + sslcheck: you may check ssl certificate (default no)  