
## custom command mispsight
This custom command is a streaming command that applies to each event.
It searches for the value of the field selected in the command.
If there are matches on MISP instance, additional fields are added related to [MISP sightings](https://www.misp.software/2017/02/16/Sighting-The-Next-Level.html)

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

    t0 is for type 0 : IOC sighted
    t1 is for type 1 : IOC false positive
    t2 is for type 2 : IOC expired

    misp_sight_t0_count : number of times sighted
    misp_sight_t0_et : timestamp when first sighted
    misp_sight_t0_first_a_id : first misp attribute_id the IOC was sighted
    misp_sight_t0_first_e_id : first misp event_id where the IOC was sighted
    misp_sight_t0_first_org_id : first misp organisation_idthe IOC was sighted
    misp_sight_t0_first_source : first source name
    misp_sight_t0_last_a_id : last misp attribute_id the IOC was sighted
    misp_sight_t0_last_e_id : last misp event_id where the IOC was sighted
    misp_sight_t0_last_org_id : last misp organisation_idthe IOC was sighted
    misp_sight_t0_last_source : last source name
    misp_sight_t0_lt : timestamp when last sighted