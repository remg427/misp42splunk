# mispgetioc

## Description

The `mispgetioc` command retrieves Indicators of Compromise (IOCs) from a configured MISP (Malware Information Sharing Platform) instance. This is a **generating command** that must be the first in a Splunk search or subsearch pipeline. The results are displayed in a structured table, ready for further processing or analysis within Splunk.

### Features

- Retrieves attributes from MISP events based on various filters
- Supports filtering by category, type, tags, and time-related parameters
- Can use all MISP OpenAPI parameters like the MISP REST client
- Optionally includes additional metadata such as event tags, decaying scores, and sighting information
- Outputs data in tabular format or as JSON events
- Supports pagination with configurable limits

## Syntax

```spl
| mispgetioc misp_instance=<string>  
    [json_request=<JSON>] [date=<YYYY-MM-DD[,YYYY-MM-DD]>] [eventid=<id1,id2,...>]  
    [last=<int>d|h|m] [publish_timestamp=<int>d|h|m] [timestamp=<int>d|h|m]  
    [category=<CSV string>] [decay_score_threshold=<int>] [decaying_model=<int>] 
    [exclude_decayed=<bool>] [expand_object=<bool>] [geteventtag=<bool>] 
    [include_decay_score=<bool>] [include_deleted=<bool>] [include_sightings=<bool>] 
    [limit=<int>] [not_tags=<CSV string>] [output=<fields|json>] [page=<int>] 
    [pipesplit=<bool>] [prefix=<string>] [tags=<CSV string>] [threat_level_id=<int>] 
    [to_ids=<bool>] [type=<CSV string>] [warning_list=<bool>]
```

## Parameters

### Required Parameters

- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. The configuration must be defined in the MISP42 Configuration page.

### Time/Event Selection Parameters (One Required)

One and only one of the following parameters must be provided:

- **json_request**
  - **Syntax:** `json_request=<JSON>`
  - **Description:** A valid JSON request payload as defined by the MISP REST API `/attributes/restSearch` endpoint.

- **date**
  - **Syntax:** `date=<YYYY-MM-DD[,YYYY-MM-DD]>`
  - **Description:** Filters events by a specific date or a range of dates (event date field).

- **eventid**
  - **Syntax:** `eventid=<id1,id2,...>`
  - **Description:** A list of event IDs or UUIDs. Multiple values can be comma-separated.

- **last**
  - **Syntax:** `last=<int>d|h|m`
  - **Description:** Retrieves events published within the last specified time interval (e.g., `5d`, `12h`, or `30m`). Alias of `publish_timestamp`.

- **publish_timestamp**
  - **Syntax:** `publish_timestamp=<int>d|h|m`
  - **Description:** Relative publication duration in day(s), hour(s) or minute(s). Supports ranges like `14d,7d`.

- **timestamp**
  - **Syntax:** `timestamp=<int>d|h|m`
  - **Description:** Event timestamp (last modification time). Supports ranges.

### Optional Filter Parameters

- **category**
  - **Syntax:** `category=<CSV string>`
  - **Description:** Filters attributes by MISP categories. Use comma-separated values. Wildcard is `%`.

- **decay_score_threshold**
  - **Syntax:** `decay_score_threshold=<int>`
  - **Description:** Overrides the threshold of the decaying model on-the-fly.

- **decaying_model**
  - **Syntax:** `decaying_model=<int>`
  - **Description:** Specifies the decaying model to use by ID.

- **exclude_decayed**
  - **Syntax:** `exclude_decayed=<bool>`
  - **Description:** Excludes decayed attributes. Default: `false`.

- **not_tags**
  - **Syntax:** `not_tags=<CSV string>`
  - **Description:** Excludes attributes with specified tags. Wildcard is `%`.

- **tags**
  - **Syntax:** `tags=<CSV string>`
  - **Description:** Filters attributes by specified tags. Wildcard is `%`.

- **threat_level_id**
  - **Syntax:** `threat_level_id=<int>`
  - **Description:** Filters by threat level (1=High, 2=Medium, 3=Low, 4=Undefined).

- **to_ids**
  - **Syntax:** `to_ids=<bool>`
  - **Description:** Filters attributes with the `to_ids` flag set to true or false.

- **type**
  - **Syntax:** `type=<CSV string>`
  - **Description:** Filters attributes by MISP types. Use comma-separated values. Wildcard is `%`.

- **warning_list**
  - **Syntax:** `warning_list=<bool>`
  - **Description:** Filters out well-known values using MISP warning lists. Default: `true`.

### Optional Output Parameters

- **expand_object**
  - **Syntax:** `expand_object=<bool>`
  - **Description:** Expands object attributes to one attribute per line. Default: `false` (attributes of an object displayed on same line).

- **geteventtag**
  - **Syntax:** `geteventtag=<bool>`
  - **Description:** Includes event tags in addition to attribute tags. Default: `true`.

- **include_decay_score**
  - **Syntax:** `include_decay_score=<bool>`
  - **Description:** Includes decay scores in the output. Default: `false`.

- **include_deleted**
  - **Syntax:** `include_deleted=<bool>`
  - **Description:** Includes deleted attributes. Default: `false`.

- **include_sightings**
  - **Syntax:** `include_sightings=<bool>`
  - **Description:** Extends response with Sightings DB results if the module is enabled. Default: `true`.

- **limit**
  - **Syntax:** `limit=<int>`
  - **Description:** Maximum number of results per page. Set to `0` for no pagination. Default: `1000`.

- **output**
  - **Syntax:** `output=<fields|json>`
  - **Description:** Output format: `fields` (tabular) or `json`. Default: `fields`.

- **page**
  - **Syntax:** `page=<int>`
  - **Description:** Specific page to retrieve when limit is not 0. Default: `0` (get all pages).

- **pipesplit**
  - **Syntax:** `pipesplit=<bool>`
  - **Description:** Splits multivalue attributes (e.g., `domain|ip`) into separate fields. Default: `true`.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** Custom prefix for all MISP keys in the output. Overrides instance default.

## Examples

### Example 1: Retrieve attributes from the last 10 days

```spl
| mispgetioc misp_instance=default_misp last=10d
```

Retrieves attributes of all events published in the last 10 days.

### Example 2: Retrieve attributes by category and type

```spl
| mispgetioc misp_instance=default_misp date="2023-01-01,2023-01-31" category="Payload delivery,Network%" type="ip-dst" to_ids=true
```

Retrieves attributes of type `ip-dst` with categories `Payload delivery` or starting with `Network` from events between January 1 and January 31, 2023, with the `to_ids` flag set.

### Example 3: Retrieve all attributes without pagination

```spl
| mispgetioc misp_instance=default_misp last=30d limit=0 tags="tlp:white"
```

Retrieves all attributes from the last 30 days tagged with `tlp:white`, without pagination limits.

### Example 4: Use JSON request for advanced queries

```spl
| mispgetioc misp_instance=default_misp json_request="{\"eventid\": [\"123\", \"456\"], \"type\": \"ip-dst\"}"
```

Uses a raw JSON request body for custom MISP API queries.

## Notes

- Boolean parameters accept values like `1`, `y`, `Y`, `t`, `true`, `True`, `0`, `n`, `N`, `f`, `false`, or `False`.
- One and only one of the following parameters must be set: `json_request`, `date`, `eventid`, `last`, `publish_timestamp`, or `timestamp`.
- Parameters like `tags`, `not_tags`, `category`, and `type` support wildcards using `%`.
- Global resource limits (max response size, max execution time) configured in MISP42 settings apply to this command.

## Logging

Logs are written to `$SPLUNK_HOME/var/log/splunk/misp42splunk.log`. Configure the logging level in the MISP42 Configuration page.

## Version

- **Current Version:** 6.0.0
- **Author:** Remi Seguy
- **License:** LGPLv3
