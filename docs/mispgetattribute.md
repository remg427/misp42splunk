# mispgetattribute

## Description
The `mispgetattribute` command retrieves a single attribute from a MISP instance based on a given ID.

## Syntax
```spl
| mispgetattribute misp_instance=<string>
[attributeid=<id>] [fields=<field1,field2,...>] [prefix=<string>]
```

## Parameters
### Required Parameters
- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. The configuration must be defined in `local/misp42splunk_instances.conf`.

### Optional Parameters
- **attributeid**
  - **Syntax:** `attributeid=<id>`
  - **Description:** The ID of the attribute. Can also be passed as defined field in each row.

- **fields**
  - **Syntax:** `fields=<field1,field2,...>`
  - **Description:** A comma-sepearted list of field names that should be returned. Leave the field empty to return all.

- **prefix**
  - **Syntax:** `prefix=<string>`
  - **Description:** Prefix for the returned field names.

## Examples

### Retrieve all attribute fields by attribute ID
```spl
| makeresults
| mispgetattribute misp_instance=default_misp attributeid=1234
```

### Retrieve specified attribute fields by attribute ID with prefix
```spl
| makeresults
| mispgetattribute misp_instance=default_misp attributeid=1234 fields=id,uuid,event_id,deleted prefix=attr_
```

### Retrieve all attribute fields by attribute ID in field
```spl
| makeresults
| eval attributeid=1234
| mispgetattribute misp_instance=default_misp
```

## Logging
Logs are written to `misp42splunk.log` and can be accessed via the Splunk job inspector. You can configure the logging level for detailed debugging information.

## Version
- **Current Version:** 5.0.0
- **Authors:** Remi Seguy, timothebot
- **License:** LGPLv3
