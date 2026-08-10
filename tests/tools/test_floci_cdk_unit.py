"""Unit tests for Floci CDK deploy helpers (no Docker)."""

from __future__ import annotations

import pytest

from tools._shared import ToolError
from tools.floci_cdk.deploy import emulator_environ
from tools.live_e2e.emulator import FLOCI_E2E_ENVIRONMENT


def test_floci_cdk_environ_requires_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(FLOCI_E2E_ENVIRONMENT, raising=False)
    with pytest.raises(ToolError, match="OPENEMR_FLOCI_E2E"):
        emulator_environ(
            endpoint_url="http://127.0.0.1:4566",
            access_key_id="test",
            secret_access_key="test",
        )


def test_floci_cdk_environ_rejects_real_aws(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLOCI_E2E_ENVIRONMENT, "1")
    with pytest.raises(ToolError, match="refuses"):
        emulator_environ(
            endpoint_url="https://sts.us-east-1.amazonaws.com",
            access_key_id="test",
            secret_access_key="test",
        )


def test_floci_cdk_environ_sets_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLOCI_E2E_ENVIRONMENT, "1")
    env = emulator_environ(
        endpoint_url="http://127.0.0.1:4566",
        access_key_id="AKIAFLOCI",
        secret_access_key="secret",
        account_id="123456789012",
        region="us-east-1",
    )
    assert env["AWS_ENDPOINT_URL"] == "http://127.0.0.1:4566"
    assert env["CDK_DEFAULT_ACCOUNT"] == "123456789012"
    assert env["AWS_ACCESS_KEY_ID"] == "AKIAFLOCI"
    assert "AWS_PROFILE" not in env
