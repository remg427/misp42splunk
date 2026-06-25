# coding=utf-8
"""Property-based tests for map_attribute_table using Hypothesis."""

from hypothesis import given, settings, assume
from hypothesis import strategies as st

from conftest import MockHelper
from misp_common import map_attribute_table


# Shared config used across all property tests
CONFIG = {
    "host": "https://misp.test",
    "prefix": "misp_",
    "pipesplit": True,
    "expand_object": False,
    "include_sightings": False,
}


def make_base_attribute(event_dict):
    """Create a minimal valid attribute with the given Event sub-dict."""
    return {
        "id": "100",
        "event_id": "1",
        "type": "ip-src",
        "value": "1.2.3.4",
        "object_id": "0",
        "Event": event_dict,
    }


# --- Property 4: ThreatLevel object flattening with fallback ---
# Validates: Requirements 4.1, 4.2, 4.3, 4.4


# Strategy for ThreatLevel.id values
threat_level_id_st = st.text(
    alphabet=st.characters(whitelist_categories=("Nd", "L")),
    min_size=1,
    max_size=5,
)

# Strategy for ThreatLevel.name values (truthy strings)
threat_level_name_st = st.text(
    alphabet=st.characters(whitelist_categories=("L", "Nd", "Zs")),
    min_size=1,
    max_size=20,
).filter(lambda s: s.strip() != "")

# Strategy for flat threat_level_id in Event dict
flat_threat_level_id_st = st.text(
    alphabet=st.characters(whitelist_categories=("Nd",)),
    min_size=1,
    max_size=3,
)


@st.composite
def threat_level_scenario(draw):
    """Generate a scenario with various ThreatLevel configurations.

    Returns a tuple of (event_dict, has_threat_level_obj, tl_has_id, tl_has_name, tl_name_truthy, has_flat_id).
    """
    # Decide whether ThreatLevel nested object is present and valid
    has_threat_level_obj = draw(st.booleans())
    # Decide whether flat threat_level_id exists in Event
    has_flat_id = draw(st.booleans())

    event_dict = {
        "id": "1",
        "info": "test event",
        "uuid": "abc-123",
        "distribution": "1",
        "publish_timestamp": "1000000",
    }

    flat_id_value = None
    if has_flat_id:
        flat_id_value = draw(flat_threat_level_id_st)
        event_dict["threat_level_id"] = flat_id_value

    tl_has_id = False
    tl_has_name = False
    tl_name_truthy = False
    tl_id_value = None
    tl_name_value = None

    if has_threat_level_obj:
        tl_has_id = draw(st.booleans())
        tl_has_name = draw(st.booleans())

        # Ensure at least one key so the dict is non-empty
        if not tl_has_id and not tl_has_name:
            # Force at least one to be present
            if draw(st.booleans()):
                tl_has_id = True
            else:
                tl_has_name = True

        threat_level = {}
        if tl_has_id:
            tl_id_value = draw(threat_level_id_st)
            threat_level["id"] = tl_id_value

        if tl_has_name:
            # name can be truthy or falsy (None, empty string)
            tl_name_truthy = draw(st.booleans())
            if tl_name_truthy:
                tl_name_value = draw(threat_level_name_st)
                threat_level["name"] = tl_name_value
            else:
                # Falsy name: None or empty string
                falsy_name = draw(st.sampled_from([None, ""]))
                threat_level["name"] = falsy_name
                tl_name_value = falsy_name
        event_dict["ThreatLevel"] = threat_level

    return {
        "event_dict": event_dict,
        "has_threat_level_obj": has_threat_level_obj,
        "tl_has_id": tl_has_id,
        "tl_has_name": tl_has_name,
        "tl_name_truthy": tl_name_truthy,
        "has_flat_id": has_flat_id,
        "flat_id_value": flat_id_value,
        "tl_id_value": tl_id_value,
        "tl_name_value": tl_name_value,
    }


@given(scenario=threat_level_scenario())
@settings(max_examples=100)
def test_threat_level_object_flattening_with_fallback(scenario):
    """Property 4: ThreatLevel object flattening with fallback.

    **Validates: Requirements 4.1, 4.2, 4.3, 4.4**

    For any attribute containing an Event sub-dictionary:
    - If a valid ThreatLevel nested dict is present, the output SHALL contain
      {prefix}threat_level_id from ThreatLevel.id (when present) and
      {prefix}threat_level_name from ThreatLevel.name (when present and truthy).
    - If no ThreatLevel object is present but a flat threat_level_id exists,
      only {prefix}threat_level_id SHALL appear.
    """
    helper = MockHelper()
    event_dict = scenario["event_dict"]
    has_threat_level_obj = scenario["has_threat_level_obj"]
    tl_has_id = scenario["tl_has_id"]
    tl_has_name = scenario["tl_has_name"]
    tl_name_truthy = scenario["tl_name_truthy"]
    has_flat_id = scenario["has_flat_id"]
    flat_id_value = scenario["flat_id_value"]
    tl_id_value = scenario["tl_id_value"]
    tl_name_value = scenario["tl_name_value"]

    attribute = make_base_attribute(event_dict)
    results = map_attribute_table(helper, [attribute], CONFIG)
    assert len(results) == 1
    record = results[0]

    prefix = CONFIG["prefix"]
    tid_key = f"{prefix}threat_level_id"
    tname_key = f"{prefix}threat_level_name"

    if has_threat_level_obj:
        # Requirement 4.1: ThreatLevel.id overrides flat threat_level_id
        if tl_has_id:
            assert tid_key in record
            assert record[tid_key] == tl_id_value
        else:
            # Requirement 4.4: ThreatLevel present but id missing,
            # fall back to flat threat_level_id if available
            if has_flat_id:
                assert tid_key in record
                assert record[tid_key] == flat_id_value
            else:
                assert tid_key not in record

        # Requirement 4.1, 4.3: threat_level_name only produced when name is truthy
        if tl_has_name and tl_name_truthy:
            assert tname_key in record
            assert record[tname_key] == tl_name_value
        else:
            # Requirement 4.3: null or missing name → no threat_level_name field
            assert tname_key not in record
    else:
        # No ThreatLevel object present
        # Requirement 4.2: use flat threat_level_id if present
        if has_flat_id:
            assert tid_key in record
            assert record[tid_key] == flat_id_value
        else:
            assert tid_key not in record

        # Requirement 4.2: no threat_level_name when no ThreatLevel object
        assert tname_key not in record


# --- Property 5: Legacy response field set preservation ---

# Legacy Event keys and their expected output field names (prefixed)
LEGACY_EVENT_KEYS = {
    "distribution": "event_distribution",
    "id": "event_id",
    "info": "event_info",
    "org_id": "org_id",
    "orgc_id": "orgc_id",
    "publish_timestamp": "publish_timestamp",
    "uuid": "event_uuid",
}

# MISP 2.5-specific output fields that must NOT appear for legacy responses
MISP25_FORBIDDEN_FIELDS = [
    f"{CONFIG['prefix']}user_id",
    f"{CONFIG['prefix']}analysis",
    f"{CONFIG['prefix']}event_date",
    f"{CONFIG['prefix']}event_timestamp",
    f"{CONFIG['prefix']}org_name",
    f"{CONFIG['prefix']}org_uuid",
    f"{CONFIG['prefix']}orgc_name",
    f"{CONFIG['prefix']}orgc_uuid",
    f"{CONFIG['prefix']}threat_level_name",
]


@st.composite
def legacy_event_subset(draw):
    """Generate a legacy-format Event sub-dict with a random subset of legacy keys.

    No nested objects (Org, Orgc, ThreatLevel) and no MISP 2.5 metadata fields.
    """
    keys_to_include = draw(
        st.lists(
            st.sampled_from(list(LEGACY_EVENT_KEYS.keys())),
            min_size=1,
            max_size=7,
            unique=True,
        )
    )

    event = {}
    for key in keys_to_include:
        if key == "distribution":
            event[key] = draw(st.sampled_from(["0", "1", "2", "3", "4"]))
        elif key == "id":
            event[key] = draw(st.integers(min_value=1, max_value=999999).map(str))
        elif key == "info":
            event[key] = draw(
                st.text(
                    alphabet=st.characters(
                        whitelist_categories=("L", "N", "P", "Z"),
                        blacklist_characters="\x00",
                    ),
                    min_size=1,
                    max_size=100,
                )
            )
        elif key == "org_id":
            event[key] = draw(st.integers(min_value=1, max_value=9999).map(str))
        elif key == "orgc_id":
            event[key] = draw(st.integers(min_value=1, max_value=9999).map(str))
        elif key == "publish_timestamp":
            event[key] = draw(
                st.integers(min_value=0, max_value=2147483647).map(str)
            )
        elif key == "uuid":
            event[key] = draw(st.uuids().map(str))

    return event


@given(event_subset=legacy_event_subset())
@settings(max_examples=100)
def test_legacy_response_field_set_preservation(event_subset):
    """Property 5: Legacy response field set preservation.

    For any attribute with a Legacy_Response-format Event sub-dict (no Org, Orgc,
    ThreatLevel objects and no new metadata fields), the output SHALL contain exactly
    the legacy field set (org_id, orgc_id, event_distribution, event_id, event_info,
    publish_timestamp, event_uuid) and SHALL NOT contain any MISP 2.5-specific fields
    (user_id, analysis, event_date, event_timestamp, org_name, org_uuid, orgc_name,
    orgc_uuid, threat_level_name).

    **Validates: Requirements 5.1, 5.2, 5.4**
    """
    helper = MockHelper()
    prefix = CONFIG["prefix"]
    attribute = make_base_attribute(event_subset)
    results = map_attribute_table(helper, [attribute], CONFIG)

    assert len(results) == 1
    output = results[0]

    # Fields that also come from attribute-level mapping (event_id, event_uuid)
    # can be present even when not in the Event sub-dict, so we only check their
    # value when they ARE in the Event sub-dict.
    # Fields that are purely Event-sourced: event_distribution, event_info,
    # org_id, orgc_id, publish_timestamp.
    PURELY_EVENT_SOURCED = {"distribution", "info", "org_id", "orgc_id",
                           "publish_timestamp"}

    # Assert: each legacy key present in the Event sub-dict produces the correct
    # prefixed output field with the correct value
    for input_key, output_field in LEGACY_EVENT_KEYS.items():
        prefixed = f"{prefix}{output_field}"
        if input_key in event_subset:
            assert prefixed in output, (
                f"Expected {prefixed} in output for legacy key '{input_key}'"
            )
            if input_key == "publish_timestamp":
                # publish_timestamp is converted to int
                assert output[prefixed] == int(event_subset[input_key]), (
                    f"Expected {prefixed} to be int({event_subset[input_key]}), "
                    f"got {output[prefixed]}"
                )
            else:
                assert output[prefixed] == event_subset[input_key], (
                    f"Expected {prefixed} == {event_subset[input_key]!r}, "
                    f"got {output[prefixed]!r}"
                )
        elif input_key in PURELY_EVENT_SOURCED:
            # Purely event-sourced field must NOT appear if not in Event sub-dict
            assert prefixed not in output, (
                f"Did not expect {prefixed} when '{input_key}' not in Event"
            )

    # Assert: no MISP 2.5-specific fields are present
    for forbidden in MISP25_FORBIDDEN_FIELDS:
        assert forbidden not in output, (
            f"MISP 2.5 field {forbidden} must NOT appear for legacy response"
        )


# --- Property 6: MISP 2.5 response completeness ---
# Validates: Requirements 5.3


@st.composite
def complete_misp25_event(draw):
    """Generate a complete MISP 2.5-format Event sub-dict.

    Includes all legacy fields, all new scalar metadata fields,
    and all nested objects (Org, Orgc, ThreatLevel) with full keys.
    """
    # Legacy scalar fields
    event_id = draw(st.integers(min_value=1, max_value=999999).map(str))
    distribution = draw(st.sampled_from(["0", "1", "2", "3", "4"]))
    info = draw(
        st.text(
            alphabet=st.characters(
                whitelist_categories=("L", "N", "P", "Z"),
                blacklist_characters="\x00",
            ),
            min_size=1,
            max_size=80,
        )
    )
    flat_org_id = draw(st.integers(min_value=1, max_value=9999).map(str))
    flat_orgc_id = draw(st.integers(min_value=1, max_value=9999).map(str))
    publish_timestamp = draw(
        st.integers(min_value=0, max_value=2147483647).map(str)
    )
    uuid = draw(st.uuids().map(str))

    # New MISP 2.5 scalar fields
    user_id = draw(st.integers(min_value=1, max_value=9999).map(str))
    flat_threat_level_id = draw(st.sampled_from(["1", "2", "3", "4"]))
    analysis = draw(st.sampled_from(["0", "1", "2"]))
    date = draw(
        st.dates(
            min_value=__import__("datetime").date(2000, 1, 1),
            max_value=__import__("datetime").date(2030, 12, 31),
        ).map(lambda d: d.isoformat())
    )
    event_timestamp = draw(
        st.integers(min_value=0, max_value=2147483647).map(str)
    )

    # Nested Org object (complete)
    org_id = draw(st.integers(min_value=1, max_value=9999).map(str))
    org_name = draw(
        st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
            min_size=1,
            max_size=30,
        )
    )
    org_uuid = draw(st.uuids().map(str))

    # Nested Orgc object (complete)
    orgc_id = draw(st.integers(min_value=1, max_value=9999).map(str))
    orgc_name = draw(
        st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Zs")),
            min_size=1,
            max_size=30,
        )
    )
    orgc_uuid = draw(st.uuids().map(str))

    # Nested ThreatLevel object (complete)
    threat_level_id = draw(st.sampled_from(["1", "2", "3", "4"]))
    threat_level_name = draw(
        st.sampled_from(["High", "Medium", "Low", "Undefined"])
    )

    event_dict = {
        # Legacy fields
        "id": event_id,
        "distribution": distribution,
        "info": info,
        "org_id": flat_org_id,
        "orgc_id": flat_orgc_id,
        "publish_timestamp": publish_timestamp,
        "uuid": uuid,
        # New MISP 2.5 scalar fields
        "user_id": user_id,
        "threat_level_id": flat_threat_level_id,
        "analysis": analysis,
        "date": date,
        "timestamp": event_timestamp,
        # Nested objects
        "Org": {"id": org_id, "name": org_name, "uuid": org_uuid},
        "Orgc": {"id": orgc_id, "name": orgc_name, "uuid": orgc_uuid},
        "ThreatLevel": {"id": threat_level_id, "name": threat_level_name},
    }

    return {
        "event_dict": event_dict,
        "expected": {
            # Legacy fields
            "event_id": event_id,
            "event_distribution": distribution,
            "event_info": info,
            "publish_timestamp": int(publish_timestamp),
            "event_uuid": uuid,
            # Org flattened (from nested Org object, overrides flat)
            "org_id": org_id,
            "org_name": org_name,
            "org_uuid": org_uuid,
            # Orgc flattened (from nested Orgc object, overrides flat)
            "orgc_id": orgc_id,
            "orgc_name": orgc_name,
            "orgc_uuid": orgc_uuid,
            # New MISP 2.5 scalar fields
            "user_id": user_id,
            "analysis": analysis,
            "event_date": date,
            "event_timestamp": int(event_timestamp),
            # ThreatLevel flattened (from nested ThreatLevel object, overrides flat)
            "threat_level_id": threat_level_id,
            "threat_level_name": threat_level_name,
        },
    }


@given(scenario=complete_misp25_event())
@settings(max_examples=100)
def test_misp25_response_completeness(scenario):
    """Property 6: MISP 2.5 response completeness.

    **Validates: Requirements 5.3**

    For any attribute with a complete MISP25_Response-format Event sub-dict
    (containing all nested objects and all metadata fields), the output SHALL
    contain both the legacy fields and all MISP 2.5-specific fields.
    """
    helper = MockHelper()
    prefix = CONFIG["prefix"]
    event_dict = scenario["event_dict"]
    expected = scenario["expected"]

    attribute = make_base_attribute(event_dict)
    results = map_attribute_table(helper, [attribute], CONFIG)

    assert len(results) == 1
    output = results[0]

    # Assert every expected field is present with the correct value
    for field_name, expected_value in expected.items():
        prefixed_key = f"{prefix}{field_name}"
        assert prefixed_key in output, (
            f"Expected field {prefixed_key} missing from output. "
            f"Output keys: {sorted(output.keys())}"
        )
        assert output[prefixed_key] == expected_value, (
            f"Field {prefixed_key}: expected {expected_value!r}, "
            f"got {output[prefixed_key]!r}"
        )


# --- Property 7: Tag extraction preserves all names with trimming ---
# Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5


# Strategy for valid tag name strings (including galaxy-style references)
_valid_tag_name_st = st.one_of(
    # Simple tag names (e.g., "tlp:white", "type:osint")
    st.text(
        alphabet=st.characters(
            whitelist_categories=("L", "N", "P", "S"),
            blacklist_characters="\x00",
        ),
        min_size=1,
        max_size=60,
    ),
    # Galaxy-style references (e.g., 'misp-galaxy:mitre-attack-pattern="T1234"')
    st.builds(
        lambda galaxy, value: f'misp-galaxy:{galaxy}="{value}"',
        galaxy=st.sampled_from([
            "mitre-attack-pattern",
            "country",
            "sector",
            "threat-actor",
        ]),
        value=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N", "Pd")),
            min_size=1,
            max_size=30,
        ),
    ),
)

# Strategy for tag name values with optional surrounding whitespace
_tag_name_with_whitespace_st = st.builds(
    lambda ws_before, name, ws_after: ws_before + name + ws_after,
    ws_before=st.sampled_from(["", " ", "  ", "\t", "\n"]),
    name=_valid_tag_name_st,
    ws_after=st.sampled_from(["", " ", "  ", "\t", "\n"]),
)

# Strategy for invalid tag name values (non-string or None)
_invalid_tag_name_st = st.one_of(
    st.none(),
    st.integers(min_value=-100, max_value=100),
    st.lists(st.text(max_size=5), max_size=3),
    st.dictionaries(st.text(max_size=5), st.text(max_size=5), max_size=2),
)


@st.composite
def tag_entry_st(draw):
    """Generate a single tag entry dict with either a valid or invalid name."""
    is_valid = draw(st.booleans())
    entry = {"id": str(draw(st.integers(min_value=1, max_value=9999)))}

    if is_valid:
        name = draw(_tag_name_with_whitespace_st)
        entry["name"] = name
        return entry, name.strip()  # Return entry and expected trimmed name
    else:
        # Invalid name: None, missing, or non-string
        has_name_key = draw(st.booleans())
        if has_name_key:
            entry["name"] = draw(_invalid_tag_name_st)
        # If has_name_key is False, entry has no 'name' key at all
        return entry, None  # None signals this entry should be skipped


@st.composite
def tag_value_scenario(draw):
    """Generate a Tag value scenario: list of dicts, single dict, empty list, None, or missing.

    Returns (tag_value, expected_names, tag_is_missing) where:
    - tag_value: value to set for 'Tag' key (or sentinel for missing)
    - expected_names: list of expected trimmed name strings in output
    - tag_is_missing: True if 'Tag' key should be absent from attribute
    """
    variant = draw(st.sampled_from([
        "list_of_dicts",
        "single_dict",
        "empty_list",
        "none",
        "missing",
    ]))

    if variant == "list_of_dicts":
        entries_with_expected = draw(
            st.lists(tag_entry_st(), min_size=0, max_size=10)
        )
        entries = [e for e, _ in entries_with_expected]
        expected = [name for _, name in entries_with_expected if name is not None]
        return entries, expected, False

    elif variant == "single_dict":
        entry, expected_name = draw(tag_entry_st())
        expected = [expected_name] if expected_name is not None else []
        return entry, expected, False

    elif variant == "empty_list":
        return [], [], False

    elif variant == "none":
        return None, [], False

    else:  # "missing"
        return None, [], True


@given(scenario=tag_value_scenario())
@settings(max_examples=100)
def test_tag_extraction_preserves_names_with_trimming(scenario):
    """Property 7: Tag extraction preserves all names with trimming.

    **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5**

    For any attribute with a Tag value (list of dicts, single dict, or empty/null),
    the output {prefix}tag field SHALL be a list containing the whitespace-trimmed
    name string from each tag entry that has a valid string name, preserving the full
    name including galaxy-style references, and skipping entries with null/missing/
    non-string names.
    """
    tag_value, expected_names, tag_is_missing = scenario
    helper = MockHelper()
    prefix = CONFIG["prefix"]

    attribute = {
        "id": "200",
        "event_id": "2",
        "type": "ip-dst",
        "value": "10.0.0.1",
        "object_id": "0",
    }

    if not tag_is_missing:
        attribute["Tag"] = tag_value
    # If tag_is_missing, we don't set the 'Tag' key at all

    results = map_attribute_table(helper, [attribute], CONFIG)
    assert len(results) == 1
    record = results[0]

    tag_key = f"{prefix}tag"

    # The tag field should always be present as a list
    assert tag_key in record, f"Expected {tag_key} in output"
    assert isinstance(record[tag_key], list), f"Expected {tag_key} to be a list"

    # The list should contain exactly the expected trimmed names in order
    assert record[tag_key] == expected_names, (
        f"Expected {tag_key} == {expected_names!r}, got {record[tag_key]!r}"
    )


# --- Property 8: Graceful handling of malformed nested objects ---
# Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5

# Malformed values that are NOT valid non-empty dicts
MALFORMED_ORG_VALUES = [None, {}, "string", 42, [1, 2, 3]]
MALFORMED_ORGC_VALUES = [None, {}, "string", 99, ["a"]]
MALFORMED_THREAT_LEVEL_VALUES = [None, {}, "high", 0, []]


@st.composite
def malformed_nested_objects_event(draw):
    """Generate an Event sub-dict where Org, Orgc, and/or ThreatLevel have malformed values.

    Each nested object key is independently set to a malformed value drawn from
    null, empty dict, string, int, or list.
    """
    event = {
        "id": "1",
        "info": "test event",
        "uuid": "abc-def-123",
        "distribution": "1",
        "publish_timestamp": "1000000",
    }

    # Decide which malformed nested objects to include
    include_org = draw(st.booleans())
    include_orgc = draw(st.booleans())
    include_threat_level = draw(st.booleans())

    # Ensure at least one malformed object is present
    if not include_org and not include_orgc and not include_threat_level:
        choice = draw(st.sampled_from(["org", "orgc", "threat_level"]))
        if choice == "org":
            include_org = True
        elif choice == "orgc":
            include_orgc = True
        else:
            include_threat_level = True

    org_value = None
    orgc_value = None
    threat_level_value = None

    if include_org:
        org_value = draw(st.sampled_from(MALFORMED_ORG_VALUES))
        event["Org"] = org_value

    if include_orgc:
        orgc_value = draw(st.sampled_from(MALFORMED_ORGC_VALUES))
        event["Orgc"] = orgc_value

    if include_threat_level:
        threat_level_value = draw(st.sampled_from(MALFORMED_THREAT_LEVEL_VALUES))
        event["ThreatLevel"] = threat_level_value

    # Optionally include flat fallback values (which may still be produced)
    if draw(st.booleans()):
        event["org_id"] = "5"
    if draw(st.booleans()):
        event["orgc_id"] = "7"
    if draw(st.booleans()):
        event["threat_level_id"] = "2"

    return {
        "event": event,
        "include_org": include_org,
        "include_orgc": include_orgc,
        "include_threat_level": include_threat_level,
        "org_value": org_value,
        "orgc_value": orgc_value,
        "threat_level_value": threat_level_value,
    }


@given(scenario=malformed_nested_objects_event())
@settings(max_examples=100)
def test_graceful_handling_of_malformed_nested_objects(scenario):
    """Property 8: Graceful handling of malformed nested objects.

    **Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5**

    For any attribute with an Event sub-dictionary where Org, Orgc, or ThreatLevel
    keys have values that are null, empty dicts, or non-dict types, the
    Attribute_Mapper SHALL not raise an exception and SHALL not produce fields
    derived from those malformed objects.
    """
    helper = MockHelper()
    prefix = CONFIG["prefix"]
    event_dict = scenario["event"]

    attribute = make_base_attribute(event_dict)

    # The function must not raise any exception
    results = map_attribute_table(helper, [attribute], CONFIG)

    assert len(results) == 1
    record = results[0]

    # When Org is malformed: no org_name, no org_uuid derived from nested object
    if scenario["include_org"]:
        assert f"{prefix}org_name" not in record, (
            f"Malformed Org ({scenario['org_value']!r}) should not produce org_name"
        )
        assert f"{prefix}org_uuid" not in record, (
            f"Malformed Org ({scenario['org_value']!r}) should not produce org_uuid"
        )

    # When Orgc is malformed: no orgc_name, no orgc_uuid derived from nested object
    if scenario["include_orgc"]:
        assert f"{prefix}orgc_name" not in record, (
            f"Malformed Orgc ({scenario['orgc_value']!r}) should not produce orgc_name"
        )
        assert f"{prefix}orgc_uuid" not in record, (
            f"Malformed Orgc ({scenario['orgc_value']!r}) should not produce orgc_uuid"
        )

    # When ThreatLevel is malformed: no threat_level_name derived from nested object
    if scenario["include_threat_level"]:
        assert f"{prefix}threat_level_name" not in record, (
            f"Malformed ThreatLevel ({scenario['threat_level_value']!r}) "
            f"should not produce threat_level_name"
        )
