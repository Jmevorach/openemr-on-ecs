"""Unit tests for utility functions."""

import pytest

from openemr_ecs.utils import (
    get_resource_suffix,
    is_live_e2e_emulated,
    is_true,
    s3_auto_delete_objects,
)


class TestIsTrue:
    """Tests for is_true utility function."""

    def test_is_true_with_string_true(self):
        """Test that string 'true' returns True."""
        assert is_true("true") is True
        assert is_true("True") is True
        assert is_true("TRUE") is True
        assert is_true("TrUe") is True

    def test_is_true_with_false_values(self):
        """Test that non-true values return False."""
        assert is_true("false") is False
        assert is_true("False") is False
        assert is_true("FALSE") is False
        assert is_true("") is False
        assert is_true("0") is False
        assert is_true("1") is False
        assert is_true("yes") is False
        assert is_true("no") is False

    def test_is_true_with_none(self):
        """Test that None returns False."""
        assert is_true(None) is False


class TestGetResourceSuffix:
    """Tests for get_resource_suffix utility function."""

    def test_get_resource_suffix_with_value(self):
        """Test that provided suffix is returned."""
        context = {"openemr_resource_suffix": "production"}
        assert get_resource_suffix(context) == "production"

    def test_get_resource_suffix_with_default(self):
        """Test that default suffix is returned when not provided."""
        context = {}
        assert get_resource_suffix(context) == "default"

    def test_get_resource_suffix_with_empty_context(self):
        """Test that default suffix is returned with empty context."""
        context = {"other_key": "value"}
        assert get_resource_suffix(context) == "default"


class TestLiveE2EEmulationGuard:
    """Tests for the production-CDK Floci boundary."""

    def test_context_alone_cannot_enable_emulation(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("OPENEMR_FLOCI_E2E", raising=False)
        monkeypatch.delenv("OPENEMR_AWS_ENDPOINT_URL", raising=False)
        monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)

        context = {"live_e2e_emulated": "true"}
        assert is_live_e2e_emulated(context) is False
        assert s3_auto_delete_objects(context) is True

    def test_local_endpoint_and_explicit_flag_enable_emulation(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENEMR_FLOCI_E2E", "1")
        monkeypatch.setenv("OPENEMR_AWS_ENDPOINT_URL", "http://127.0.0.1:4566")

        context = {"live_e2e_emulated": "true"}
        assert is_live_e2e_emulated(context) is True
        assert s3_auto_delete_objects(context) is False

    def test_real_aws_endpoint_cannot_enable_emulation(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("OPENEMR_FLOCI_E2E", "1")
        monkeypatch.setenv("AWS_ENDPOINT_URL", "https://sts.us-east-1.amazonaws.com")

        assert is_live_e2e_emulated({"live_e2e_emulated": "true"}) is False

    @pytest.mark.parametrize("host", ["10.0.0.5", "172.16.0.5", "192.168.1.5", "floci.local"])
    def test_remote_private_endpoint_cannot_enable_emulation(self, monkeypatch: pytest.MonkeyPatch, host: str):
        monkeypatch.setenv("OPENEMR_FLOCI_E2E", "1")
        monkeypatch.setenv("AWS_ENDPOINT_URL", f"http://{host}:4566")

        assert is_live_e2e_emulated({"live_e2e_emulated": "true"}) is False
