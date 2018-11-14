
## custom command mispsearch
This custom command is a streaming command that applies to each event.
It searches for the value of the field selected in the command.
If there are matches, additional multi-value fields (starting by misp_) are added to the dataset.

The command syntax is as follow:

    search something... | mispsearch field=<field_containing_value_to_search_for> 
                [onlyids=y|n]
                [gettag_comment=y|n]
                [misp_url=https://host:port] 
                [misp_key=misp-authorization-key]
                [misp_verifycert=y|n]                 
                

one simple example:

    ... | field clientip | mispsearch field=clientip | dedup misp_json

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

- If you need to fecth from another MISP instance different from the default one defined in the setup of the app, you may overwrite the misp server parameters for this search by setting
    + misp_url: set the url to the MISP instance
    + misp_key: misp-authorization-key for this instance
    + misp_verifycert: you may check ssl certificate (default no)  