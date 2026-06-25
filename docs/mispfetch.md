# mispfetch

## Description

The `mispfetch` command is a **streaming command** that pulls events or attributes from a MISP instance and **appends** them to the current dataset. Unlike `mispgetioc` and `mispgetevent`, this command can dynamically build MISP queries from SPL fields.

### Features

- Streaming command that appends MISP data to existing results
- All MISP REST API parameters can be built dynamically from SPL fields
- Supports both `/events/restSearch` and `/attributes/restSearch` endpoints
- Parameters can be set via SPL fields (priority) or command arguments
- Output in tabular or JSON format

### mispfetch vs mispgetioc/mispgetevent

| Feature | mispfetch | mispgetioc/mispgetevent |
|---------|-----------|-------------------------|
| Command Type | Streaming | Generating |
| Position | Cannot be first line | Must be first line |
| Dynamic Parameters | Yes, via SPL fields | No, arguments only |
| Use Case | Dynamic queries, enrichment | Static queries |

## Syntax

```spl
... | mispfetch 
    [misp_instance=<string>] [misp_restsearch=<events|attributes>] 
    [misp_http_body=<JSON>] [misp_output_mode=<fields|json>]
    [attribute_limit=<int>] [expand_object=<bool>] [getioc=<bool>] 
    [keep_galaxy=<bool>] [keep_related=<bool>] [limit=<int>] 
    [not_tags=<CSV string>] [page=<int>] [pipesplit=<bool>] 
    [prefix=<string>] [tags=<CSV string>]
```

## Parameters

All parameters can be set as SPL fields (using `eval`) or as command arguments. **Field values take priority over command arguments.**

### Required Parameters

- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. Must be a valid instance name defined in the MISP42 Configuration page.

### Optional Query Parameters

- **misp_restsearch**
  - **Syntax:** `misp_restsearch=<events|attributes>`
  - **Description:** MISP REST endpoint to use. Default: `events`.

- **misp_http_body**
  - **Syntax:** `misp_http_body=<JSON>`
  - **Description:** Valid JSON request body for the MISP API. Use `tojson` command to build dynamically. If not provided, defaults to `{"last": "1h", "published": true}`.

- **limit**
  - **Syntax:** `limit=<int>`
  - **Description:** Maximum results per page. Default: `1000`. Set to `0` for no pagination.

- **page**
  - **Syntax:** `page=<int>`
  - **Description:** Specific page to retrieve. Default: `0` (get all pages).

- **tags**
  - **Syntax:** `tags=<CSV string>`
  - **Description:** Comma-separated list of tags to include. Wildcard is `%`.

- **not_tags**
  - **Syntax:** `not_tags=<CSV string>`
  - **Description:** Comma-separated list of tags to exclude. Wildcard is `%`.

### Optional Output Parameters

- **misp_output_mode**
  - **Syntax:** `misp_output_mode=<fields|json>`
  - **Description:** Output format: `fields` (tabular) or `json`. Default: `fields`.

- **attribute_limit**
  - **Syntax:** `attribute_limit=<int>`
  - **Description:** Maximum attributes per event when `getioc=true`. Default: `0` (no limit).

- **expand_object**
  - **Syntax:** `expand_object=<bool>`
  - **Description:** Expands object attributes to one per line. Default: `false`.

- **getioc**
  - **Syntax:** `getioc=<bool>`
  - **Description:** Include attributes with events. Default: `false`.

- **keep_galaxy**
  - **Syntax:** `keep_galaxy=<bool>`
  - **Description:** Retain galaxy information in output. Default: `false`.

- **keep_related**
  - **Syntax:** `keep_related=<bool>`
  - **Description:** Include related events. Default: `false`.

- **pipesplit**
  - **Syntax:** `pipesplit=<bool>`
  - **Description:** Split multivalue attributes. Default: `true`.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** Custom prefix for MISP keys.

## Examples

### Example 1: Basic usage with defaults

```spl
| makeresults
| eval misp_instance="default_misp"
| mispfetch
```

Retrieves published events from the last hour (default behavior).

### Example 2: Dynamic query with tojson

```spl
| makeresults
| eval misp_instance="default_misp", last="7d", published=true, type="ip-dst"
| tojson last, published, type output_field=misp_http_body
| mispfetch getioc=true limit=100 attribute_limit=500
```

Retrieves up to 100 published events from the last 7 days with ip-dst attributes, including up to 500 attributes per event.

### Example 3: Query attributes endpoint

```spl
| makeresults
| eval misp_instance="default_misp", misp_restsearch="attributes"
| eval last="30d", to_ids=true
| tojson last, to_ids output_field=misp_http_body
| mispfetch limit=5000
```

Retrieves attributes with to_ids flag from the last 30 days.

### Example 4: Filter by tags

```spl
| makeresults
| eval misp_instance="default_misp"
| eval last="14d"
| tojson last output_field=misp_http_body
| mispfetch tags="malware,apt" not_tags="false-positive"
```

Retrieves events from the last 14 days tagged as malware or apt, excluding false positives.

### Example 5: JSON output mode

```spl
| makeresults
| eval misp_instance="default_misp"
| eval eventid="123,456,789"
| tojson eventid output_field=misp_http_body
| mispfetch misp_output_mode=json getioc=true
```

Retrieves specific events with full JSON output including attributes.

### Example 6: Dynamic instance selection

```spl
| inputlookup misp_queries.csv
| mispfetch
```

If the lookup contains `misp_instance` and `misp_http_body` fields, each row queries its specified instance with its parameters.

## Building the Request Body

Use the `tojson` command to easily build the `misp_http_body` field:

```spl
| eval last="7d", published=true, type="ip-dst", tags="malware"
| tojson last, published, type, tags output_field=misp_http_body
```

This creates: `{"last": "7d", "published": true, "type": "ip-dst", "tags": "malware"}`

Any parameter supported by the MISP REST API can be included in the request body.

## Notes

- If `misp_http_body` is not provided, the command defaults to `{"last": "1h", "published": true}`.
- Field values always take priority over command arguments.
- Boolean parameters accept values like `1`, `y`, `Y`, `t`, `true`, `True`, `0`, `n`, `N`, `f`, `false`, or `False`.
- Global resource limits (max response size, max execution time) configured in MISP42 settings apply to this command.
- Sightings are included by default.

## Logging

Logs are written to `$SPLUNK_HOME/var/log/splunk/misp42splunk.log`. Configure the logging level in the MISP42 Configuration page.

## Version

- **Current Version:** 6.0.0
- **Author:** Remi Seguy
- **License:** LGPLv3
