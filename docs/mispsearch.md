
## custom command mispsearch
This custom command is a streaming command that applies to each event.
It searches for the value of the field selected in the command.
If there are matches, additional multi-value fields (starting by misp_) are added to the dataset.

The command syntax is as follow:

    search something... | mispsearch field=<field_containing_value_to_search_for> 
                [onlyids=y|n]
                [gettag=y|n]
                [misp_instance=instance_name] 
                
**WARNING**: if the field contains null value, you may get a server error 500. You can use the splunk command __|fillnull field__ to avoid those errors (Thanks @jlachesk for solving this #54).
    
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
