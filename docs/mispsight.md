
## custom command mispsight
This custom command is a streaming command that applies to each event.
It searches for the value of the field selected in the command.
If there are matches, additional fields are added related to [MISP sightings](https://www.misp.software/2017/02/16/Sighting-The-Next-Level.html)

The command syntax is as follow:

    search something... | mispsight field=<field_containing_value_to_search_for> 
                [misp_url=https://host:port] 
                [misp_key=misp-authorization-key]
                [misp_verifycert=y|n]                 
                

one simple example:

    ... | field clientip | mispsight field=clientip | dedup misp_json

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

- If you need to fecth from another MISP instance different from the default one defined in the setup of the app, you may overwrite the misp server parameters for this search by setting
    + misp_url: set the url to the MISP instance
    + misp_key: misp-authorization-key for this instance
    + misp_verifycert: you may check ssl certificate (default no)  