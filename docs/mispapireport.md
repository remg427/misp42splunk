
## custom command mispapireport version 2.0
This custom command is a wrapper to call the MISP API endpoint /attributes/restSearch with the same options as direct calls.
It must be the first of a search (or a sub-search). The results are displayed in a table that contains all the fields returned by MISP API.

So the output can be immediately reused in a search without complex transforms

There are 2 main modes:

   1. mode=p : in this mode individual parameters are passed to build a JSON request on the fly. This mode is the **default one**. You can use almost all available options to build the request i.e "page", "limit", "value", "type", "category", "org", "tags" (and "not_tags"), "date_from", "date_to", "last", "eventid", "uuid", "enforceWarninglist", "to_ids", "deleted", "includeEventUuid", "includeEventTags", "threat_level_id", "eventinfo".

		| mispapireport misp_instance=default_misp mode=p type="domain,ip-src" date_from="2019-01-01"

   2. mode=j : in this mode a complete JSON request is passed as parameter using field json_request

		| mispapireport misp_instance=default_misp mode=j json_request="{\"type\": {\"OR\": [\"domain\",\"ip-dst\"]}, \"from\": \"2019-01-01\"}"

The 2 examples should return the same results as they result in the same request at the end.  

----
    Note: 
    string: for fields type, category, tags and not_tags, CSV string can be provided to search for multiple values
    wildcard: %
    Boolean: value can be <1|y|Y|t|true|True|0|n|N|f|false|False>
----
