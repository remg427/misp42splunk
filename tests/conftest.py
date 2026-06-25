# coding=utf-8
"""Shared fixtures and mocks for misp42splunk tests."""
import sys
from pathlib import Path

# Add package/bin to sys.path so misp_common can be imported directly.
# We also need to provide stubs for Splunk SDK modules that aren't available
# in the test environment.
_bin_path = str(Path(__file__).resolve().parent.parent / "package" / "bin")
if _bin_path not in sys.path:
    sys.path.insert(0, _bin_path)

# Stub out splunklib modules that misp_common imports at top-level.
# These are not needed for the pure mapping functions under test.
import types

_splunklib = types.ModuleType("splunklib")
_splunklib.client = types.ModuleType("splunklib.client")
_splunklib.data = types.ModuleType("splunklib.data")
sys.modules.setdefault("splunklib", _splunklib)
sys.modules.setdefault("splunklib.client", _splunklib.client)
sys.modules.setdefault("splunklib.data", _splunklib.data)

import pytest  # noqa: E402


class MockHelper:
    """Minimal mock for the helper object passed to map_attribute_table.

    Provides log_info and log_debug methods that record calls for inspection.
    """

    def __init__(self):
        self.logs = []

    def log_info(self, msg):
        self.logs.append(("info", msg))

    def log_debug(self, msg):
        self.logs.append(("debug", msg))


@pytest.fixture
def helper():
    """Provide a fresh MockHelper instance for each test."""
    return MockHelper()
