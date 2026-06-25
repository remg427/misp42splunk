# mispgetevent

## Description

The `mispgetevent` command retrieves event data from a MISP instance based on various parameters and filters. This is a **generating command** that must be the first in a Splunk search or subsearch pipeline. It supports tabular and JSON output formats for easy integration and analysis in Splunk searches.

### Features

- Retrieves events from MISP with optional attribute data
- Supports filtering by category, type, tags, and time-related parameters
- Can include sighting information, galaxy data, and related events
- Outputs data in tabular format or as JSON events
- Supports pagination with configurable limits

## Syntax

```spl
| mispgetevent misp_instance=<string>  
    [json_request=<JSON>] [date=<YYYY-MM-DD[,YYYY-MM-DD]>] [eventid=<id1,id2,...>]  
    [last=<int>d|h|m] [publish_timestamp=<int>d|h|m] [timestamp=<int>d|h|m] 
    [category=<CSV string>] [exclude_local_tags=<bool>] [expand_object=<bool>] 
    [getioc=<bool>] [include_sightings=<bool>] [keep_galaxy=<bool>] [keep_related=<bool>] 
    [limit=<int>] [not_tags=<CSV string>] [output=<fields|json>] [page=<int>] 
    [pipesplit=<bool>] [prefix=<string>] [published=<bool>] [tags=<CSV string>] 
    [threat_level_id=<int>] [to_ids=<bool>] [type=<CSV string>] [warning_list=<bool>]
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
  - **Description:** A valid JSON request payload as defined by the MISP REST API `/events/restSearch` endpoint.

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
  - **Description:** Filters events by attribute categories. Use comma-separated values. Wildcard is `%`.

- **exclude_local_tags**
  - **Syntax:** `exclude_local_tags=<bool>`
  - **Description:** Excludes local tags from results. Default: `false`.

- **not_tags**
  - **Syntax:** `not_tags=<CSV string>`
  - **Description:** Excludes events with specified tags. Wildcard is `%`.

- **published**
  - **Syntax:** `published=<bool>`
  - **Description:** Filters only published or unpublished events.

- **tags**
  - **Syntax:** `tags=<CSV string>`
  - **Description:** Filters events by specified tags. Wildcard is `%`.

- **threat_level_id**
  - **Syntax:** `threat_level_id=<int>`
  - **Description:** Filters by threat level (1=High, 2=Medium, 3=Low, 4=Undefined).

- **to_ids**
  - **Syntax:** `to_ids=<bool>`
  - **Description:** Filters events containing attributes with the `to_ids` flag set.

- **type**
  - **Syntax:** `type=<CSV string>`
  - **Description:** Filters events by attribute types. Use comma-separated values. Wildcard is `%`.

- **warning_list**
  - **Syntax:** `warning_list=<bool>`
  - **Description:** Filters out well-known values using MISP warning lists. Default: `true`.

### Optional Output Parameters

- **expand_object**
  - **Syntax:** `expand_object=<bool>`
  - **Description:** Expands object attributes to one attribute per line. Default: `false`.

- **getioc**
  - **Syntax:** `getioc=<bool>`
  - **Description:** Retrieves the list of attributes along with each event. Default: `false`.

- **include_sightings**
  - **Syntax:** `include_sightings=<bool>`
  - **Description:** Extends response with Sightings DB results if the module is enabled. Default: `true`.

- **keep_galaxy**
  - **Syntax:** `keep_galaxy=<bool>`
  - **Description:** Retains galaxy information in the output. Default: `true`.

- **keep_related**
  - **Syntax:** `keep_related=<bool>`
  - **Description:** Includes related events in the output. Default: `false`.

- **limit**
  - **Syntax:** `limit=<int>`
  - **Description:** Maximum number of events per page. Set to `0` for no pagination. Default: `1000`.

- **output**
  - **Syntax:** `output=<fields|json>`
  - **Description:** Output format: `fields` (tabular) or `json`. Default: `fields`.

- **page**
  - **Syntax:** `page=<int>`
  - **Description:** Specific page to retrieve when limit is not 0. Default: `0` (get all pages).

- **pipesplit**
  - **Syntax:** `pipesplit=<bool>`
  - **Description:** Splits multivalue attributes into separate fields. Default: `true`.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** Custom prefix for all MISP keys in the output. Overrides instance default.

## Examples

### Example 1: Retrieve events by event ID

```spl
| mispgetevent misp_instance=default_misp eventid=477 category="Payload delivery,Network activity" type="sha256,ip-dst"
```

Retrieves event 477 filtered to specific categories and types.

### Example 2: Retrieve events published in the last 10 days

```spl
| mispgetevent misp_instance=default_misp last=10d output=json
```

Retrieves all events published in the last 10 days as JSON objects.

### Example 3: Retrieve events with attributes

```spl
| mispgetevent misp_instance=default_misp timestamp=7d getioc=true expand_object=true
```

Retrieves events modified in the last 7 days, including all attributes with objects expanded.

### Example 4: Retrieve events in a date range

```spl
| mispgetevent misp_instance=default_misp date="2023-12-01,2023-12-31" tags="malware" published=true
```

Retrieves published events from December 2023 tagged with "malware".

### Example 5: Retrieve events between publish timestamps

```spl
| mispgetevent misp_instance=default_misp publish_timestamp="14d,7d"
```

Retrieves events published between 14 and 7 days ago.

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
