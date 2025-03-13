
# mispgetioc

## Description
The `mispgetioc` command retrieves Indicators of Compromise (IOCs) from a configured MISP (Malware Information Sharing Platform) instance. This command must be the first in a Splunk search or subsearch pipeline. The results are displayed in a structured table, ready for further processing or analysis within Splunk.

### Features
- Retrieves attributes from MISP events based on various filters.
- Supports filtering by category, type, tags, and time-related parameters.
- Can use all MISP OpenAPI parameters like the MISP REST client.
- Optionally includes additional metadata such as event tags, decaying scores, and organizational details.
- Outputs data in a format suitable for immediate reuse in Splunk searches or returns JSON events.

## Syntax
```spl
| mispgetioc misp_instance=<string>  
[json_request=<JSON>] [date=<YYYY-MM-DD[,YYYY-MM-DD]>] [eventid=<id1,id2,...>]  
[last=<int>d|h|m] [publish_timestamp=<int>d|h|m] [timestamp=<int>d|h|m]  
[category=<CSV string>] [decay_score_threshold=<int>] [decaying_model=<int>] [exclude_decayed=<bool>]  
[expand_object=<bool>] [geteventtag=<bool>] [include_decay_score=<bool>] [include_deleted=<bool>]  
[include_sightings=<bool>] [limit=<int>] [not_tags=<CSV string>]  
[output=<fields|json>] [page=<int>] [pipesplit=<bool>] [prefix=<string>] 
[tags=<CSV string>] [threat_level_id=<int>] [to_ids=<bool>] [type=<CSV string>] [warning_list=<bool>]
```

## Parameters
### Required Parameters
- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. The configuration must be defined in `local/misp42splunk_instances.conf`.

### Optional Parameters
- **json_request**
  - **Syntax:** `json_request=<JSON>`
  - **Description:** A valid JSON request payload as defined by the MISP REST API.

- **date**
  - **Syntax:** `date=<YYYY-MM-DD[,YYYY-MM-DD]>`
  - **Description:** Filters events by a specific date or a range of dates.

- **eventid**
  - **Syntax:** `eventid=<id1,id2,...>`
  - **Description:** A list of event IDs or UUIDs. Multiple values can be comma-separated.

- **last**
  - **Syntax:** `last=<int>d|h|m`
  - **Description:** Retrieves events published within the last specified time interval (e.g., `5d`, `12h`, or `30m`).

- **publish_timestamp**
  -  **Syntax:** `publish_timestamp=<int>d|h|m`
  - **Description:** relative publication duration in day(s), hour(s) or minute(s).

- **timestamp**
  - **Syntax:** `timestamp=<int>d|h|m`
  - **Description:** event timestamp (last change).

- **category**
  - **Syntax:** `category=<CSV string>`
  - **Description:** Filters attributes by MISP categories. Use a comma-separated string.

- **decay\_score\_threshold**
  - **Syntax:** `decay_score_threshold=<int>`
  - **Description:** Overrides the threshold of the decaying model.

- **decaying_model**
  - **Syntax:** `decaying_model=<int>`
  - **Description:** Specifies the decaying model to use by ID.

- **exclude_decayed**
  - **Syntax:** `exclude_decayed=<bool>`
  - **Description:** Excludes decayed attributes. Default is `false`.

- **expand_object**
  - **Syntax:** `expand_object=<bool>`
  - **Description:** Expands object attributes to one attribute per line. Default is `false`.

- **geteventtag**
  - **Syntax:** `geteventtag=<bool>`
  - **Description:** boolean includeEventTags. Default is `true`: event tags are returned in addition of any attribute tags.

- **include\_decay\_score**
  - **Syntax:** `include_decay_score=<bool>`
  - **Description:** Includes decay scores in the output. Default is `false`.

- **include_deleted**
  - **Syntax:** `include_deleted=<bool>`
  - **Description:** Includes deleted attributes. Default is `false`.

- **include_sightings**
  - **Syntax:** `include_sightings=<bool>`
  - **Description:** Boolean includeSightings. Extend response with Sightings DB results if the module is enabled. Default is `true`

- **limit**
  - **Syntax:** `limit=<int>`
  - **Description:** Specifies the maximum number of results to return. Default is `1000`.

- **not_tags**
  - **Syntax:** `not_tags=<CSV string>`
  - **Description:** Excludes attributes with specified tags.

- **output**
  - **Syntax:** `output=<fields|json>`
  - **Description:** Defines the output format. Options are `fields` (tabular) or `json`. Default is `fields`.

- **page**
  - **Syntax:** `page=<int>`
  - **Description:** define the page when limit is not 0. Default is `0`: get all pages.

- **pipesplit**
  - **Syntax:** `pipesplit=<bool>`
  - **Description:** Splits multivalue attributes into separate fields. Default is `true`.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** Adds a prefix to all MISP keys in the output.

- **tags**
  - **Syntax:** `tags=<CSV string>`
  - **Description:** Filters attributes by specified tags.

- **threat\_level\_id**
  - **Syntax:** `threat_level_id=<int>`
  - **Description:**define the threat level (1-High, 2-Medium, 3-Low, 4-Undefined).

- **to_ids**
  - **Syntax:** `to_ids=<bool>`
  - **Description:** Filters attributes with the `to_ids` flag set to true or false.

- **type**
  - **Syntax:** `type=<CSV string>`
  - **Description:** Filters attributes by MISP types. Use a comma-separated string.

- **warning_list**
  - **Syntax:** `warning_list=<bool>`
  - **Description:** boolean to filter out well known values. Default is `true`.

## Examples
### Example 1: Retrieve attributes from the last 10 days
```spl
| mispgetioc misp_instance=test last=10d
```
- Retrieves attributes of all events published in the last 10 days.

### Example 2: Retrieve attributes by category and type
```spl
| mispgetioc misp_instance=test date="2023-01-01,2023-01-31" category="Payload delivery,Network%" type="ip-dst" to_ids=true
```
- Retrieves attributes of type `ip-dst` and categories `Payload delivery` or starting with `Network` from events between January 1 and January 31, 2023.

## Notes
- Boolean parameters accept values like `1`, `y`, `Y`, `t`, `true`, `0`, `n`, `N`, `f`, or `false`.
- One and only one of the following parameters must be set: `json_request`, `date`, `eventid`, `last`, `publish_timestamp` or `timestamp`.
- Parameters like `tags` and `not_tags` support wildcards using `%`.

## Logging
Logs are written to `misp42splunk.log` and can be accessed via the Splunk job inspector. You can configure the logging level for detailed debugging information.

## Version
- **Current Version:** 5.0.0
- **Authors:** Remi Seguy
- **License:** LGPLv3
