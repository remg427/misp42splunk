# mispsearch

## Description

The `mispsearch` command is a **streaming command** that searches MISP for attributes matching the value of a specified field in each event. When matches are found, additional multi-value fields (prefixed with `misp_` by default) are added to the dataset.

### Features

- Searches MISP for attribute values from your Splunk data
- Adds MISP metadata to matching events
- Supports tag filtering and custom JSON request bodies
- Merges multiple matching attributes into multi-value fields

## Syntax

```spl
... | mispsearch misp_instance=<string> field=<fieldname>
    [misp_http_body=<JSON>] [limit=<int>] [not_tags=<CSV string>] 
    [page=<int>] [pipesplit=<bool>] [prefix=<string>] [tags=<CSV string>]
```

## Parameters

### Required Parameters

- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. The configuration must be defined in the MISP42 Configuration page.

- **field**
  - **Syntax:** `field=<fieldname>`
  - **Description:** Name of the field containing the value to search for in MISP.

### Optional Parameters

- **misp_http_body**
  - **Syntax:** `misp_http_body=<JSON>`
  - **Description:** Valid JSON request body for customized search. Note: `returnFormat` is forced to `json` and `withAttachments` to `false`.

- **limit**
  - **Syntax:** `limit=<int>`
  - **Description:** Maximum number of results per search. Default: `10`.

- **not_tags**
  - **Syntax:** `not_tags=<CSV string>`
  - **Description:** Comma-separated list of tags to exclude from the search. Wildcard is `%`.

- **page**
  - **Syntax:** `page=<int>`
  - **Description:** Page number for paginated results. Default: `1`.

- **pipesplit**
  - **Syntax:** `pipesplit=<bool>`
  - **Description:** Splits multivalue attributes into separate fields. Default: `true`.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** Custom prefix for MISP keys in the output. Default: `misp_`.

- **tags**
  - **Syntax:** `tags=<CSV string>`
  - **Description:** Comma-separated list of tags to filter the search. Wildcard is `%`.

## Output Fields

When matches are found, the following fields are added to each event:

- `misp_type` - Attribute type
- `misp_value` - Attribute value
- `misp_to_ids` - to_ids flag
- `misp_category` - Attribute category
- `misp_attribute_uuid` - Attribute UUID
- `misp_event_id` - Event ID containing the attribute
- `misp_event_uuid` - Event UUID
- `misp_tag` - Tags associated with the attribute
- `misp_attributes` - Full attribute objects as multi-value field

## Examples

### Example 1: Basic search by IP address

```spl
index=firewall sourcetype=palo_traffic
| mispsearch misp_instance=default_misp field=dest_ip
| where isnotnull(misp_event_id)
```

Searches MISP for destination IPs found in firewall logs.

### Example 2: Search with custom prefix

```spl
index=proxy 
| fields clientip 
| mispsearch misp_instance=default_misp field=clientip prefix="threat_"
| dedup threat_event_id
```

Searches for client IPs with a custom field prefix.

### Example 3: Search with tag filtering

```spl
index=dns 
| fields query 
| mispsearch misp_instance=default_misp field=query tags="malware,c2" not_tags="false-positive"
```

Searches for DNS queries, filtering to attributes tagged as malware or C2, excluding false positives.

### Example 4: Advanced search with JSON body

```spl
index=email 
| fields src_email 
| mispsearch misp_instance=default_misp field=src_email misp_http_body="{\"includeEventTags\": true, \"includeEventUuid\": true, \"type\": \"email-src\"}"
```

Uses a custom JSON request body to narrow the search to email-src attribute types.

## Notes

- **WARNING**: If the field contains null values, you may get a server error 500. Use `| fillnull <field>` before calling mispsearch to avoid these errors.
- Boolean parameters accept values like `1`, `y`, `Y`, `t`, `true`, `True`, `0`, `n`, `N`, `f`, `false`, or `False`.
- The command automatically sets `returnFormat=json`, `withAttachments=false`, `includeEventTags=true`, and `includeEventUuid=true`.
- Values that are empty, null, `0`, or `%` are skipped.
- Sightings are included by default (`includeSightings=true`).

## Logging

Logs are written to `$SPLUNK_HOME/var/log/splunk/misp42splunk.log`. Configure the logging level in the MISP42 Configuration page.

## Version

- **Current Version:** 6.0.0
- **Author:** Remi Seguy
- **License:** LGPLv3
