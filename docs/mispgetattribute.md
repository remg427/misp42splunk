# mispgetattribute

## Description

The `mispgetattribute` command is a **streaming command** that retrieves details for a single MISP attribute by its ID. The attribute ID is read from a specified field in each record, allowing batch lookups of multiple attributes.

### Features

- Retrieves full attribute details from MISP
- Supports filtering to specific output fields
- Processes each record independently
- Adds MISP attribute data to existing events

## Syntax

```spl
... | mispgetattribute misp_instance=<string> attributeid=<fieldname>
    [output_filter=<field1,field2,...>] [prefix=<string>]
```

## Parameters

### Required Parameters

- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. The configuration must be defined in the MISP42 Configuration page.

- **attributeid**
  - **Syntax:** `attributeid=<fieldname>`
  - **Description:** Name of the field containing the attribute ID to look up. The field value must be a valid numeric attribute ID.

### Optional Parameters

- **output_filter**
  - **Syntax:** `output_filter=<field1,field2,...>`
  - **Description:** Comma-separated list of MISP attribute fields to return. If not specified, all fields are returned.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** Custom prefix for the returned field names. Default: `misp_`.

## Output Fields

When an attribute is found, the following fields may be added (depending on `output_filter`):

- `misp_id` - Attribute ID
- `misp_uuid` - Attribute UUID
- `misp_event_id` - Parent event ID
- `misp_type` - Attribute type
- `misp_category` - Attribute category
- `misp_value` - Attribute value
- `misp_to_ids` - to_ids flag
- `misp_timestamp` - Attribute timestamp
- `misp_comment` - Attribute comment
- `misp_deleted` - Deletion status
- `misp_first_seen` - First seen timestamp
- `misp_last_seen` - Last seen timestamp
- `misp_object_id` - Parent object ID (if part of an object)
- `misp_object_relation` - Object relation (if part of an object)

## Examples

### Example 1: Retrieve all attribute fields by ID

```spl
| makeresults 
| eval attr_id=1234 
| mispgetattribute misp_instance=default_misp attributeid=attr_id
```

Retrieves all fields for the attribute with ID 1234.

### Example 2: Retrieve specific fields with custom prefix

```spl
| makeresults 
| eval attr_id=1234 
| mispgetattribute misp_instance=default_misp attributeid=attr_id output_filter="event_id,type,value,deleted" prefix="attr_"
```

Retrieves only event_id, type, value, and deleted fields with `attr_` prefix.

### Example 3: Batch lookup from search results

```spl
index=misp_alerts 
| fields attribute_id 
| mispgetattribute misp_instance=default_misp attributeid=attribute_id
| table attribute_id, misp_type, misp_value, misp_event_id
```

Looks up attribute details for each attribute_id found in the search results.

### Example 4: Enrich existing data

```spl
| inputlookup my_ioc_list.csv 
| mispgetattribute misp_instance=default_misp attributeid=misp_attribute_id output_filter="deleted,to_ids"
| where misp_deleted="false" AND misp_to_ids="true"
```

Enriches a lookup table with current attribute status from MISP.

## Notes

- The `attributeid` parameter must reference a field containing a valid numeric attribute ID.
- Invalid attribute IDs (non-numeric values) are logged as warnings and the record is returned unchanged.
- If the attribute is not found in MISP, an error message is added to `<prefix>error_message`.
- Boolean parameters accept values like `1`, `y`, `Y`, `t`, `true`, `True`, `0`, `n`, `N`, `f`, `false`, or `False`.

## Logging

Logs are written to `$SPLUNK_HOME/var/log/splunk/misp42splunk.log`. Configure the logging level in the MISP42 Configuration page.

## Version

- **Current Version:** 6.0.0
- **Authors:** Remi Seguy, timothebot
- **License:** LGPLv3
