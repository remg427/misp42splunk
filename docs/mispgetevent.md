# mispgetevent

## Description
The `mispgetevent` command retrieves event data from a MISP instance based on various parameters and filters. It supports 2 output formats for easy integration and analysis in Splunk searches.

## Syntax
```
| mispgetevent misp_instance=<string>  
[json_request=<JSON>] [date=<YYYY-MM-DD[,YYYY-MM-DD]>] [eventid=<id1,id2,...>]  
[last=<int>d|h|m] [publish_timestamp=<int>d|h|m] [timestamp=<int>d|h|m] 
[category=<CSV string>] [exclude_local_tags=<bool>] [expand_object=<bool>] [getioc=<bool>] 
[include_sightings=<bool>] [keep_galaxy=<bool>] [keep_related=<bool>] 
[limit=<int>] [not_tags=<CSV string>] [output=<fields|json>] [page=<int>] 
[pipesplit=<bool>] [prefix=<string>] [published=<bool>] [tags=<CSV string>] 
[threat_level_id=<int>] [to_ids=<bool>] [type=<CSV string>] [warning_list=<bool>]
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
  - **Description:** Comma-separated list of categories to filter events. Wildcard is `%`.

- **exclude_local_tags**
  - **Syntax:** `exclude_local_tags=<bool>`
  - **Description:** excludeLocalTags. Default is `false`.

- **expand_object**
  - **Syntax:** `expand_object=<bool>`
  - **Description:** Expands object attributes to one attribute per line. Default is `false`.

- **getioc**
  - **Syntax:** `getioc=<bool>`
  - **Description:** Retrieves the list of attributes along with the event. Default is `false`.

- **include_sightings**
  - **Syntax:** `include_sightings=<bool>`
  - **Description:** Extends the response with Sightings DB results if enabled. Default is `true`.

- **keep_galaxy**
  - **Syntax:** `keep_galaxy=<bool>`
  - **Description:** Retains galaxy information in the output. Default is `false`.

- **keep_related**
  - **Syntax:** `keep_related=<bool>`
  - **Description:** Includes related events per attribute in the output. Default is `false`.

- **limit**
  - **Syntax:** `limit=<int>`
  - **Description:** Limits the number of events retrieved. Default is `1000`.

- **not_tags**
  - **Syntax:** `not_tags=<CSV string>`
  - **Description:** Comma-separated list of tags to exclude from the search. Wildcard is `%`.

- **output**
  - **Syntax:** `output=<fields|json>`
  - **Description:** Determines the output format: `fields` (default tabular view) or `json`.

- **page**
  - **Syntax:** `page=<int>`
  - **Description:** Specifies the page number for paginated results. Default is `0` (fetches all pages).

- **pipesplit**
  - **Syntax:** `pipesplit=<bool>`
  - **Description:** Splits multivalue attributes into separate rows. Default is `true`.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** A string prefix for MISP keys.

- **published**
  - **Syntax:** `published=<bool>`
  - **Description:** Filters only published events.

- **tags**
  - **Syntax:** `tags=<CSV string>`
  - **Description:** Comma-separated list of tags to include in the search. Wildcard is `%`.

- **threat\_level\_id**
  - **Syntax:** `threat_level_id=<int>`
  - **Description:** Filters events by threat level (1-High, 2-Medium, 3-Low, 4-Undefined).

- **to_ids**
  - **Syntax:** `to_ids=<bool>`
  - **Description:** Filters attributes with the `to_ids` flag set to true.

- **type**
  - **Syntax:** `type=<CSV string>`
  - **Description:** Comma-separated list of types to include in the search. Wildcard is `%`.

- **warning_list**
  - **Syntax:** `warning_list=<bool>`
  - **Description:** Filters out known values. Default is `true`.

## Usage
The `mispgetevent` command must be the first in a search or sub-search. It retrieves event data and optionally the attributes in the MISP events and transforms for further processing.

## Examples

### Retrieve events by event ID
```
| mispgetevent misp_instance=default_misp eventid=477 category="Payload delivery,Network activity" type="sha256,ip-dst"
```

### Retrieve events published in the last 10 days
```
| mispgetevent misp_instance=test output=json last=10d
```

### Retrieve events using a custom date filter
```
| mispgetevent misp_instance=default_misp date="2023-12-01" tags="malware"
```

### Retrieve events with expanded object attributes
```
| mispgetevent misp_instance=default_misp expand_object=true
```

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

