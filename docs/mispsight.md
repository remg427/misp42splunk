
## custom command mispsight
This custom command is a streaming command that applies to each event.
It searches for the value of the field selected in the command.
If there are matches, additional fields are added related to [MISP sightings](https://www.misp.software/2017/02/16/Sighting-The-Next-Level.html)

The command syntax is as follow:

    search something... | mispsight field=<field_containing_value_to_search_for> 
                [misp_instance=instance_name] 
                
**WARNING**: if the field contains null value, you may get a server error 500. You can use the splunk command **|fillnull field** to avoid those errors (Thanks @jlachesk for solving this #54).

one simple example:

    ... | field clientip | mispsight field=clientip misp_instance=default_misp 

will add following fields 

    misp_value
    misp_fp  # if one attribute is tagged as false positive
    misp_fp_timestamp
    misp_fp_event_id

    misp_sight_count #if sighting has been set
    misp_sight_first
    misp_sight_first_event_id
    misp_sight_last
    misp_sight_last_event_id
