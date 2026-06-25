# misprest

## Description

The `misprest` command is a **generating command** that serves as a generic wrapper to call any MISP REST API endpoint. This is the most versatile command in the MISP42 add-on, allowing direct access to all MISP API functionality.

### Features

- Supports all HTTP methods: GET, POST, PUT, DELETE
- Can call any MISP API endpoint
- Returns raw JSON responses from MISP
- Useful for operations not covered by other commands

## Syntax

```spl
| misprest misp_instance=<string> 
    [method=<DELETE|GET|POST|PUT>] [target=<string>] [json_request=<JSON>]
```

## Parameters

### Required Parameters

- **misp_instance**
  - **Syntax:** `misp_instance=<string>`
  - **Description:** Specifies the MISP instance to use. The configuration must be defined in the MISP42 Configuration page.

### Optional Parameters

- **method**
  - **Syntax:** `method=<DELETE|GET|POST|PUT>`
  - **Description:** HTTP method to use for the API call. Default: `GET`.

- **target**
  - **Syntax:** `target=<string>`
  - **Description:** Target MISP API endpoint path (must start with `/`). Default: `/servers/serverSettings`.

- **json_request**
  - **Syntax:** `json_request=<JSON>`
  - **Description:** JSON-formatted request body for POST/PUT requests.

## Examples

### Example 1: Get MISP server version

```spl
| misprest misp_instance=default_misp method=GET target="/servers/getVersion"
```

Retrieves the MISP server version information.

### Example 2: Search attributes with custom parameters

```spl
| misprest misp_instance=default_misp method=POST target="/attributes/restSearch" json_request="{\"returnFormat\": \"json\", \"last\": \"20d\", \"type\": \"ip-dst\"}"
```

Retrieves attributes of type ip-dst from events published in the last 20 days.

### Example 3: Get all tags

```spl
| misprest misp_instance=default_misp method=GET target="/tags"
```

Retrieves all tags from the MISP instance.

### Example 4: Get server settings

```spl
| misprest misp_instance=default_misp method=GET target="/servers/serverSettings"
```

Retrieves MISP server configuration settings.

### Example 5: Search events by organisation

```spl
| misprest misp_instance=default_misp method=POST target="/events/restSearch" json_request="{\"org\": \"CIRCL\", \"limit\": 10}"
```

Searches for the 10 most recent events from organisation "CIRCL".

### Example 6: Get sharing groups

```spl
| misprest misp_instance=default_misp method=GET target="/sharing_groups"
```

Retrieves all sharing groups available to the user.

### Example 7: Get a specific event

```spl
| misprest misp_instance=default_misp method=GET target="/events/view/123"
```

Retrieves details of event with ID 123.

### Example 8: Get galaxies

```spl
| misprest misp_instance=default_misp method=GET target="/galaxies"
```

Retrieves all galaxies from MISP.

## Common API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/servers/getVersion` | GET | Get MISP version |
| `/servers/serverSettings` | GET | Get server settings |
| `/events/restSearch` | POST | Search events |
| `/attributes/restSearch` | POST | Search attributes |
| `/tags` | GET | List all tags |
| `/galaxies` | GET | List all galaxies |
| `/sharing_groups` | GET | List sharing groups |
| `/organisations` | GET | List organisations |
| `/events/view/<id>` | GET | Get specific event |
| `/attributes/view/<id>` | GET | Get specific attribute |

## Notes

- The response is returned as a single Splunk event with `_raw` containing the JSON response.
- When using `json_request`, remember to escape double quotes: `\"`
- For complex queries, consider preparing the JSON in a field before calling misprest.
- Refer to the [MISP REST API documentation](https://www.misp-project.org/openapi/) for available endpoints and parameters.

## Logging

Logs are written to `$SPLUNK_HOME/var/log/splunk/misp42splunk.log`. Configure the logging level in the MISP42 Configuration page.

## Version

- **Current Version:** 6.0.0
- **Author:** Remi Seguy
- **License:** LGPLv3
