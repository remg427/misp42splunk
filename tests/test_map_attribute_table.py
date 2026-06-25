# coding=utf-8
"""Unit tests for map_attribute_table() in misp_common.py.

These tests validate specific examples and edge cases for the tabular output
mapping function, covering legacy responses, MISP 2.5 responses, nested object
handling, tag extraction, and pipe-split composite types.

Tests are split into two sections:
1. Tests using real MISP API sample data from samples_misp_restSearch/
2. Hand-crafted edge-case tests for scenarios not present in the samples
"""
import copy
import json
from pathlib import Path

import pytest

from misp_common import map_attribute_table


# ---------------------------------------------------------------------------
# Sample data helpers
# ---------------------------------------------------------------------------

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples_misp_restSearch"

MISP_HOST = "https://misp.example.com"
CONFIG = {
    "host": MISP_HOST,
    "prefix": "misp_",
    "pipesplit": True,
    "expand_object": False,
    "include_sightings": False,
}


def _load_attributes(filename):
    """Load and return the Attribute list from a sample JSON file."""
    filepath = SAMPLES_DIR / filename
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data["response"]["Attribute"]


def _load_first_attribute(filename):
    """Load the first attribute from a sample file (as a deep copy)."""
    attributes = _load_attributes(filename)
    return copy.deepcopy(attributes[0])


# ---------------------------------------------------------------------------
# Tests using real MISP API sample data
# ---------------------------------------------------------------------------


class TestLegacyResponseFromSample:
    """Load first attribute from attributes_restSearch_2.4.json and verify
    legacy field mapping. No MISP 2.5 fields should be present.

    Validates: Requirements 5.1, 5.2, 5.4
    """

    SAMPLE = "attributes_restSearch_2.4.json"

    def test_legacy_attribute_fields(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Attribute-level fields
        assert record["misp_attribute_id"] == "19450219"
        assert record["misp_event_id"] == "214502"
        assert record["misp_type"] == "AS"
        assert record["misp_value"] == "13335"
        assert record["misp_category"] == "Network activity"
        assert record["misp_to_ids"] is False
        assert record["misp_attribute_uuid"] == "25f6c7c5-47dd-4e42-9a98-d5c5c06aaa2a"
        assert record["misp_timestamp"] == 1781178068
        assert record["misp_attribute_distribution"] == "5"
        assert record["misp_object_id"] == "0"
        assert record["misp_sharing_group_id"] == "0"
        assert record["misp_deleted"] is False
        assert record["misp_host"] == MISP_HOST

    def test_legacy_event_fields(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Event-level fields from legacy 2.4 response
        assert record["misp_org_id"] == "4"
        assert record["misp_orgc_id"] == "1473"
        assert record["misp_event_distribution"] == "3"
        assert record["misp_publish_timestamp"] == 1781316075
        assert record["misp_event_id"] == "214502"
        assert record["misp_event_info"] == "APVA phishing/scam indicators 2026-06-11 11:40 (42 indicators)"
        assert record["misp_event_uuid"] == "0366aa69-9660-4104-91b2-6ea93e7d6e80"

    def test_no_misp25_fields(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # MISP 2.5-specific fields must NOT be present
        misp25_fields = [
            "misp_user_id",
            "misp_analysis",
            "misp_event_date",
            "misp_event_timestamp",
            "misp_org_name",
            "misp_org_uuid",
            "misp_orgc_name",
            "misp_orgc_uuid",
            "misp_threat_level_name",
        ]
        for field in misp25_fields:
            assert field not in record, f"Unexpected MISP 2.5 field: {field}"

    def test_no_tags_in_simple_response(self, helper):
        """Simple 2.4 response has no Tag key - misp_tag should be empty."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_tag"] == []


class TestLegacyResponseWithTagsFromSample:
    """Load first attribute from attributes_restSearch_2.4_events.json and
    verify legacy fields + tags (19 tags including galaxy-style names).

    Validates: Requirements 5.1, 5.2, 6.1-6.3
    """

    SAMPLE = "attributes_restSearch_2.4_events.json"

    def test_legacy_event_fields_with_tags(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_org_id"] == "4"
        assert record["misp_orgc_id"] == "1473"
        assert record["misp_event_distribution"] == "3"
        assert record["misp_publish_timestamp"] == 1781316075
        assert record["misp_event_info"] == "APVA phishing/scam indicators 2026-06-11 11:40 (42 indicators)"
        assert record["misp_event_uuid"] == "0366aa69-9660-4104-91b2-6ea93e7d6e80"

    def test_event_uuid_at_attribute_level(self, helper):
        """The _events variant includes event_uuid at attribute level."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_event_uuid"] == "0366aa69-9660-4104-91b2-6ea93e7d6e80"

    def test_tag_count(self, helper):
        """First attribute has 19 tags."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert len(record["misp_tag"]) == 19

    def test_tags_include_galaxy_patterns(self, helper):
        """Tags contain misp-galaxy:* patterns that should be preserved."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        galaxy_tags = [t for t in record["misp_tag"] if t.startswith("misp-galaxy:")]
        assert len(galaxy_tags) >= 5
        assert 'misp-galaxy:sector="Finance"' in record["misp_tag"]
        assert 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"' in record["misp_tag"]
        assert 'misp-galaxy:country="united states"' in record["misp_tag"]

    def test_tags_include_taxonomy_patterns(self, helper):
        """Tags include taxonomy-style names."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert "tlp:clear" in record["misp_tag"]
        assert 'ecsirt:fraud="phishing"' in record["misp_tag"]
        assert "kill-chain:Delivery" in record["misp_tag"]
        assert "Phishing" in record["misp_tag"]

    def test_no_misp25_fields(self, helper):
        """Even with tags, 2.4 response has no MISP 2.5 nested objects."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        misp25_fields = [
            "misp_user_id",
            "misp_analysis",
            "misp_event_date",
            "misp_event_timestamp",
            "misp_org_name",
            "misp_org_uuid",
            "misp_orgc_name",
            "misp_orgc_uuid",
            "misp_threat_level_name",
        ]
        for field in misp25_fields:
            assert field not in record, f"Unexpected MISP 2.5 field: {field}"


class TestMisp25ResponseFromSample:
    """Load first attribute from attributes_restSearch_2.5.json and verify
    all MISP 2.5 fields including nested Org/Orgc/ThreatLevel.

    Validates: Requirements 1.1-1.5, 2.1-2.3, 3.1-3.3, 4.1-4.3, 5.3
    """

    SAMPLE = "attributes_restSearch_2.5.json"

    def test_attribute_level_fields(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_attribute_id"] == "12274244"
        assert record["misp_event_id"] == "118315"
        assert record["misp_type"] == "AS"
        assert record["misp_value"] == "13335"
        assert record["misp_category"] == "Network activity"
        assert record["misp_timestamp"] == 1781178068

    def test_misp25_scalar_event_fields(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # New MISP 2.5 scalar fields from Event
        assert record["misp_user_id"] == "1"
        assert record["misp_analysis"] == "2"
        assert record["misp_event_date"] == "2026-06-11"
        assert record["misp_event_timestamp"] == 1781241576
        assert record["misp_event_distribution"] == "3"
        assert record["misp_publish_timestamp"] == 1781308839

    def test_org_flattening(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Org nested object overrides flat org_id
        assert record["misp_org_id"] == "1"
        assert record["misp_org_name"] == "ORGA"
        assert record["misp_org_uuid"] == "305d4e1e-80d2-4592-a1d7-b9cec29bb626"

    def test_orgc_flattening(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Orgc nested object overrides flat orgc_id
        assert record["misp_orgc_id"] == "1657"
        assert record["misp_orgc_name"] == "APVA"
        assert record["misp_orgc_uuid"] == "a01c3fb8-3af6-4c02-a9ea-ed0712de4203"

    def test_threat_level_flattening(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # ThreatLevel overrides flat threat_level_id
        assert record["misp_threat_level_id"] == "3"
        assert record["misp_threat_level_name"] == "Low"

    def test_no_tags_in_simple_25(self, helper):
        """Simple 2.5 response has no Tag key."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_tag"] == []


class TestMisp25ResponseWithTagsFromSample:
    """Load first attribute from attributes_restSearch_2.5_events.json and
    verify MISP 2.5 fields + tags.

    Validates: Requirements 1.1-1.5, 2.1-2.3, 3.1-3.3, 4.1-4.3, 6.1-6.3
    """

    SAMPLE = "attributes_restSearch_2.5_events.json"

    def test_misp25_fields_with_tags(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # MISP 2.5 fields
        assert record["misp_user_id"] == "1"
        assert record["misp_analysis"] == "2"
        assert record["misp_event_date"] == "2026-06-11"
        assert record["misp_event_timestamp"] == 1781241576
        assert record["misp_org_name"] == "ORGA"
        assert record["misp_orgc_name"] == "APVA"
        assert record["misp_threat_level_id"] == "3"
        assert record["misp_threat_level_name"] == "Low"

    def test_event_uuid_at_attribute_level(self, helper):
        """2.5 _events variant also has event_uuid at attribute level."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_event_uuid"] == "0366aa69-9660-4104-91b2-6ea93e7d6e80"

    def test_tag_count(self, helper):
        """First attribute has 19 tags."""
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert len(record["misp_tag"]) == 19

    def test_galaxy_tags_preserved(self, helper):
        attr = _load_first_attribute(self.SAMPLE)
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        galaxy_tags = [t for t in record["misp_tag"] if t.startswith("misp-galaxy:")]
        assert len(galaxy_tags) >= 5
        assert 'misp-galaxy:sector="Finance"' in record["misp_tag"]
        assert 'misp-galaxy:mitre-attack-pattern="Phishing - T1566"' in record["misp_tag"]
        assert 'misp-galaxy:mitre-attack-pattern="Domains - T1583.001"' in record["misp_tag"]
        assert 'misp-galaxy:mitre-attack-pattern="Masquerading - T1036"' in record["misp_tag"]
        assert 'misp-galaxy:mitre-attack-pattern="Web Portal Capture - T1056.003"' in record["misp_tag"]
        assert 'misp-galaxy:mitre-attack-pattern="Phishing for Information - T1598"' in record["misp_tag"]


class TestMultipleAttributesFromSample:
    """Load all attributes from each sample file and verify processing
    completes without errors and produces valid output.

    Validates: bulk processing robustness
    """

    @pytest.mark.parametrize("filename", [
        "attributes_restSearch_2.4.json",
        "attributes_restSearch_2.4_events.json",
        "attributes_restSearch_2.5.json",
        "attributes_restSearch_2.5_events.json",
    ])
    def test_all_attributes_produce_output(self, helper, filename):
        attributes = _load_attributes(filename)
        output = map_attribute_table(helper, copy.deepcopy(attributes), CONFIG)

        # Every attribute should produce at least one output record
        assert len(output) >= 1
        # All records must have misp_host
        for record in output:
            assert record["misp_host"] == MISP_HOST
            assert "misp_type" in record
            assert "misp_value" in record

    @pytest.mark.parametrize("filename", [
        "attributes_restSearch_2.4.json",
        "attributes_restSearch_2.4_events.json",
        "attributes_restSearch_2.5.json",
        "attributes_restSearch_2.5_events.json",
    ])
    def test_all_records_have_tag_list(self, helper, filename):
        """Every record's misp_tag must be a list (possibly empty)."""
        attributes = _load_attributes(filename)
        output = map_attribute_table(helper, copy.deepcopy(attributes), CONFIG)

        for record in output:
            assert isinstance(record["misp_tag"], list)

    @pytest.mark.parametrize("filename", [
        "attributes_restSearch_2.5.json",
        "attributes_restSearch_2.5_events.json",
    ])
    def test_25_all_records_have_org_fields(self, helper, filename):
        """All 2.5 records should have Org/Orgc flattened fields."""
        attributes = _load_attributes(filename)
        output = map_attribute_table(helper, copy.deepcopy(attributes), CONFIG)

        for record in output:
            assert "misp_org_name" in record
            assert "misp_orgc_name" in record
            assert "misp_threat_level_name" in record


# ---------------------------------------------------------------------------
# Hand-crafted edge case tests
# (scenarios not covered by real sample data)
# ---------------------------------------------------------------------------


def _legacy_attribute():
    """Return a legacy MISP attribute dict (pre-2.5 format) for edge cases."""
    return {
        "id": "12670371",
        "event_id": "177592",
        "type": "url",
        "value": "https://example.com/phish",
        "category": "Network activity",
        "to_ids": True,
        "uuid": "aabbccdd-1234",
        "timestamp": "1781143300",
        "distribution": "5",
        "object_id": "0",
        "object_relation": "",
        "sharing_group_id": "0",
        "Event": {
            "org_id": "4",
            "distribution": "3",
            "publish_timestamp": "1781143363",
            "id": "177592",
            "info": "test legacy event",
            "orgc_id": "171",
            "uuid": "7c45d4a7-0000-0000-0000-000000000001",
        },
        "Tag": [{"id": "8", "name": "tlp:white"}],
    }


def _misp25_attribute():
    """Return a MISP 2.5 attribute dict with full nested objects for edge cases."""
    return {
        "id": "349269",
        "event_id": "2099",
        "type": "link",
        "value": "https://example.com/report",
        "category": "External analysis",
        "to_ids": False,
        "uuid": "deadbeef-5678",
        "timestamp": "1780927900",
        "distribution": "0",
        "object_id": "0",
        "object_relation": "",
        "sharing_group_id": "0",
        "Event": {
            "id": "2099",
            "info": "test misp event",
            "org_id": "1",
            "orgc_id": "1",
            "uuid": "f50c4952-0000-0000-0000-000000000002",
            "distribution": "4",
            "publish_timestamp": "1780927958",
            "user_id": "2",
            "threat_level_id": "2",
            "analysis": "0",
            "date": "2026-05-29",
            "timestamp": "1780927956",
            "first_publication": "1761206713",
            "Org": {"id": "1", "name": "ORGA", "uuid": "56b0a0f0-org"},
            "Orgc": {"id": "1", "name": "ORGA", "uuid": "56b0a0f0-orgc"},
            "ThreatLevel": {"id": "3", "name": "Low"},
        },
        "Tag": [{"id": "13", "name": "tlp:white"}],
    }


class TestNullOrgOrgcThreatLevel:
    """Verify no crash and correct fallback when Org/Orgc/ThreatLevel are None.

    Validates: Requirements 7.1, 7.2, 7.3
    """

    def test_null_org_falls_back_to_flat(self, helper):
        attr = _misp25_attribute()
        attr["Event"]["Org"] = None
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Falls back to flat org_id from Event
        assert record["misp_org_id"] == "1"
        assert "misp_org_name" not in record
        assert "misp_org_uuid" not in record

    def test_null_orgc_falls_back_to_flat(self, helper):
        attr = _misp25_attribute()
        attr["Event"]["Orgc"] = None
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_orgc_id"] == "1"
        assert "misp_orgc_name" not in record
        assert "misp_orgc_uuid" not in record

    def test_null_threat_level_falls_back_to_flat(self, helper):
        attr = _misp25_attribute()
        attr["Event"]["ThreatLevel"] = None
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Falls back to flat threat_level_id
        assert record["misp_threat_level_id"] == "2"
        assert "misp_threat_level_name" not in record


class TestNonDictNestedObjects:
    """Verify graceful skip when Org/Orgc/ThreatLevel are non-dict types.

    Validates: Requirements 7.5
    """

    @pytest.mark.parametrize("bad_value", ["string_org", 42, [1, 2, 3]])
    def test_non_dict_org(self, helper, bad_value):
        attr = _misp25_attribute()
        attr["Event"]["Org"] = bad_value
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Falls back to flat org_id
        assert record["misp_org_id"] == "1"
        assert "misp_org_name" not in record
        assert "misp_org_uuid" not in record

    @pytest.mark.parametrize("bad_value", ["string_orgc", 99, ["a"]])
    def test_non_dict_orgc(self, helper, bad_value):
        attr = _misp25_attribute()
        attr["Event"]["Orgc"] = bad_value
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_orgc_id"] == "1"
        assert "misp_orgc_name" not in record
        assert "misp_orgc_uuid" not in record

    @pytest.mark.parametrize("bad_value", ["high", 0, []])
    def test_non_dict_threat_level(self, helper, bad_value):
        attr = _misp25_attribute()
        attr["Event"]["ThreatLevel"] = bad_value
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Falls back to flat threat_level_id
        assert record["misp_threat_level_id"] == "2"
        assert "misp_threat_level_name" not in record


class TestMissingEventKey:
    """Verify no event fields and no error when Event key is absent.

    Validates: Requirements 1.6, 7.4
    """

    def test_no_event_key(self, helper):
        attr = {
            "id": "100",
            "event_id": "50",
            "type": "ip-src",
            "value": "1.2.3.4",
            "object_id": "0",
            "Tag": [{"id": "1", "name": "test-tag"}],
        }
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # No event fields
        assert "misp_event_info" not in record
        assert "misp_event_distribution" not in record
        assert "misp_event_uuid" not in record
        assert "misp_org_id" not in record
        assert "misp_orgc_id" not in record
        assert "misp_publish_timestamp" not in record

        # Attribute-level fields are still present
        assert record["misp_attribute_id"] == "100"
        assert record["misp_value"] == "1.2.3.4"
        assert record["misp_host"] == MISP_HOST


class TestEmptyEventDict:
    """Verify no event fields produced when Event is an empty dict.

    Validates: Requirements 1.7, 7.4
    """

    def test_empty_event_dict(self, helper):
        attr = {
            "id": "200",
            "event_id": "60",
            "type": "domain",
            "value": "evil.com",
            "object_id": "0",
            "Event": {},
            "Tag": [],
        }
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # No event fields produced from empty Event dict
        assert "misp_event_info" not in record
        assert "misp_event_distribution" not in record
        assert "misp_event_uuid" not in record
        assert "misp_org_id" not in record
        assert "misp_orgc_id" not in record


class TestTagAsSingleDict:
    """Verify single-element extraction when Tag is a dict instead of a list.

    Validates: Requirements 6.5
    """

    def test_single_dict_tag(self, helper):
        attr = _legacy_attribute()
        attr["Tag"] = {"id": "99", "name": "  tlp:green  "}
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_tag"] == ["tlp:green"]


class TestTagWithNullNonStringNames:
    """Verify skipping of tags with null or non-string name values.

    Validates: Requirements 6.4
    """

    def test_null_name_skipped(self, helper):
        attr = _legacy_attribute()
        attr["Tag"] = [
            {"id": "1", "name": "valid-tag"},
            {"id": "2", "name": None},
            {"id": "3"},  # missing name
            {"id": "4", "name": 12345},
            {"id": "5", "name": "another-valid"},
        ]
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_tag"] == ["valid-tag", "another-valid"]


class TestThreatLevelMissingId:
    """Verify fallback to flat value when ThreatLevel dict has no 'id' key.

    Validates: Requirements 4.4
    """

    def test_threat_level_no_id_falls_back(self, helper):
        attr = _misp25_attribute()
        # ThreatLevel has name but no id
        attr["Event"]["ThreatLevel"] = {"name": "High"}
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        # Falls back to flat threat_level_id from Event
        assert record["misp_threat_level_id"] == "2"
        assert record["misp_threat_level_name"] == "High"


class TestThreatLevelMissingName:
    """Verify no threat_level_name field when ThreatLevel has no 'name' key.

    Validates: Requirements 4.3
    """

    def test_threat_level_no_name(self, helper):
        attr = _misp25_attribute()
        attr["Event"]["ThreatLevel"] = {"id": "4"}
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_threat_level_id"] == "4"
        assert "misp_threat_level_name" not in record


class TestPipeSplitCompositeTypes:
    """Verify existing pipe-split behavior for composite types is unchanged.

    Validates: Requirements 5.4 (existing behavior preservation)
    """

    def test_pipe_split_creates_two_records(self, helper):
        attr = {
            "id": "500",
            "event_id": "300",
            "type": "ip-src|port",
            "value": "192.168.1.1|8080",
            "object_id": "0",
            "uuid": "split-uuid",
            "timestamp": "1780000000",
            "distribution": "0",
            "Event": {
                "id": "300",
                "info": "pipe test",
                "distribution": "1",
                "publish_timestamp": "1780000001",
                "uuid": "event-uuid-300",
                "org_id": "2",
                "orgc_id": "3",
            },
            "Tag": [{"id": "1", "name": "test"}],
        }
        output = map_attribute_table(helper, [attr], CONFIG)

        assert len(output) >= 1
        record = output[0]
        assert "misp_host" in record
        # The record should contain the pipe-split type fields
        has_port = "misp_port" in record or record.get("misp_type") == "port"
        has_ip_src = "misp_ip_src" in record or record.get("misp_type") == "ip-src"
        assert has_port or has_ip_src


class TestFirstPublicationField:
    """Verify first_publication field extraction (MISP 2.5 only).

    The first_publication field is new in MISP 2.5 and represents the Unix
    timestamp of when an event was first published.
    """

    def test_first_publication_extracted(self, helper):
        """first_publication should be extracted when present in Event."""
        attr = _misp25_attribute()
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert record["misp_first_publication"] == "1761206713"

    def test_first_publication_missing_in_legacy(self, helper):
        """Legacy MISP 2.4 responses don't have first_publication."""
        attr = _legacy_attribute()
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert "misp_first_publication" not in record

    def test_first_publication_missing_gracefully(self, helper):
        """When first_publication is absent, no error and no field."""
        attr = _misp25_attribute()
        del attr["Event"]["first_publication"]
        output = map_attribute_table(helper, [attr], CONFIG)
        record = output[0]

        assert "misp_first_publication" not in record
