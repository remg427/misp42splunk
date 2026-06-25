# Alert Actions

MISP42 provides two alert actions to push data from Splunk to MISP:

1. **MISP Create Event** - Create or update MISP events
2. **MISP Sighting** - Record sightings for attributes

## MISP Create Event

This alert action creates new MISP events or updates existing ones based on search results.

### Features

- Create new events or update existing events
- Add attributes and objects (file, email, domain-ip)
- Support for all MISP distribution levels
- Configurable threat level, analysis status, TLP, and PAP
- Automatic or manual event publication
- Group results into multiple events using a unique key field

### Preparing Search Results

Structure your search results with properly named fields:

```spl
| eval misp_ip_dst=dest_ip
| eval misp_domain=query
| eval fo_md5=file_hash, fo_filename=file_name
| eval misp_info="Suspicious activity detected"
| eval misp_tag="malware,apt"
| table misp_* fo_*
```

#### Field Naming Conventions

| Prefix | Description | Example |
|--------|-------------|---------|
| `misp_` | Standard MISP attributes | `misp_ip_dst`, `misp_domain`, `misp_md5` |
| `fo_` | File object attributes | `fo_md5`, `fo_sha256`, `fo_filename` |
| `eo_` | Email object attributes | `eo_from`, `eo_subject`, `eo_to` |
| `no_` | Domain-IP object attributes | `no_domain`, `no_ip` |

**Note:** The `misp_` prefix is removed and underscores are converted to hyphens for the MISP attribute type. For example, `misp_ip_dst` becomes type `ip-dst`.

#### Special Inline Fields

| Field | Description |
|-------|-------------|
| `misp_info` | Event info field (per row) |
| `misp_date` | Event date as EPOCH timestamp |
| `misp_tag` | Additional event tags (comma-separated) |
| `misp_publish_event` | Set to `1` to publish this event (overrides alert config) |
| `misp_sg_id` | Sharing group ID (when distribution=4) |
| `misp_category` | Attribute category |
| `misp_comment` | Attribute comment |
| `misp_to_ids` | Set to `True` or `False` |
| `misp_attribute_tag` | Tags for attributes (comma-separated) |
| `misp_first_seen` | First seen timestamp (EPOCH) |
| `misp_last_seen` | Last seen timestamp (EPOCH) |

### Alert Configuration

#### Required Settings

- **MISP Instance**: Select the MISP instance to use
- **Title**: Alert title (for Splunk documentation)
- **Description**: Alert description

#### Event Parameters

- **Event (UU)ID**: Existing event ID/UUID to update (leave blank to create new)
- **Unique identifier**: Field name to group rows into separate events
- **MISP Info**: Default info field if not provided in results
- **Distribution**: 
  - 0 = Your organisation only (default)
  - 1 = This community only
  - 2 = Connected communities
  - 3 = All communities
  - 4 = Sharing Group (requires `misp_sg_id` field)
- **Threat Level**: 1=High, 2=Medium, 3=Low, 4=Undefined (default)
- **Analysis**: 0=Initial (default), 1=Ongoing, 2=Complete
- **TLP**: WHITE, CLEAR, GREEN, AMBER, AMBER+STRICT, RED
- **PAP**: WHITE, GREEN, AMBER, RED
- **Publish Event**: YES/NO - whether to publish after creation/modification
- **Tags**: Additional tags (comma-separated)

### Example: Create Event via Alert

1. Save your search as an alert
2. Add action "MISP Create Event"
3. Configure the form parameters
4. The alert will create/update MISP events when triggered

### Example: Create Event via sendalert

```spl
index=sandbox sourcetype=analysis
| eval misp_ip_dst=dest_ip, fo_md5=file_hash, fo_filename=file_name
| table misp_* fo_*
| sendalert misp_alert_create_event \
    param.misp_instance=default_misp \
    param.title="Sandbox Alert" \
    param.distribution=0 \
    param.threatlevel=3 \
    param.analysis=0 \
    param.tlp="TLP_AMBER" \
    param.pap="PAP_AMBER" \
    param.publish_event=0
```

### Notes

- For objects, verify attribute names in the [MISP Object definitions](https://github.com/MISP/misp-objects/tree/master/objects)
- The API may create duplicate objects if you submit the same inputs multiple times
- Additional field-to-attribute mappings can be added via `lookups/misp_datatypes.csv`

---

## MISP Sighting

This alert action records sightings for MISP attributes, incrementing their sighting counters.

### Features

- Sighting by attribute value or UUID
- Support for all sighting types (standard, false positive, expiration)
- Custom timestamp and source fields
- Batch processing of multiple sightings

### Preparing Search Results

```spl
index=proxy 
| lookup misp_ioc_lookup value as url OUTPUT misp_attribute_uuid
| where isnotnull(misp_attribute_uuid)
| table misp_attribute_uuid, _time, source
```

### Alert Configuration

#### Required Settings

- **MISP Instance**: Select the MISP instance to use
- **Title**: Alert title
- **Mode**: 
  - `byvalue` - Sighting for matching attribute values
  - `byuuid` - Sighting for attribute UUID in field `misp_attribute_uuid`
- **Type**:
  - 0 = Standard sighting (default STIX interpretation)
  - 1 = False positive
  - 2 = Expiration sighting

#### Optional Settings

- **Description**: Alert description
- **Timestamp**: Field containing timestamps (default: current time)
- **Source**: Source identifier for the sighting

### Example: Sighting via Alert

1. Save your search as an alert
2. Add action "Alert for sighting MISP attribute(s)"
3. Configure mode (byvalue or byuuid) and type
4. The alert will record sightings when triggered

### Example: Sighting via sendalert

```spl
index=firewall 
| lookup misp_ioc_lookup value as src_ip OUTPUT misp_attribute_uuid
| where isnotnull(misp_attribute_uuid)
| table misp_attribute_uuid
| sendalert misp_alert_sighting \
    param.misp_instance=default_misp \
    param.title="Firewall Sighting" \
    param.mode=byuuid \
    param.type=0
```

### Sighting by Value

```spl
index=dns 
| stats count by query
| where count > 100
| table query
| sendalert misp_alert_sighting \
    param.misp_instance=default_misp \
    param.title="DNS Sighting" \
    param.mode=byvalue \
    param.type=0
```

### Notes

- For mode `byuuid`, only the first UUID is kept if the field is multi-value
- Use `mvdedup` and `mvexpand` to handle multi-value UUID fields if needed
- Timestamp field should contain EPOCH values

---

## Logging

Alert action logs are written to:
- Create Event: `$SPLUNK_HOME/var/log/splunk/misp_alert_create_event_modalert.log`
- Sighting: `$SPLUNK_HOME/var/log/splunk/misp_alert_sighting_modalert.log`

## Version

- **Current Version:** 6.0.0
- **Author:** Remi Seguy
- **License:** LGPLv3
