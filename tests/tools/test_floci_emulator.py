"""Unit tests for Floci/live-E2E emulator guards (no Docker required)."""

from __future__ import annotations

from pathlib import Path

import pytest

from tools._shared import ToolError
from tools.live_e2e.emulator import (
    FLOCI_E2E_ENVIRONMENT,
    assert_safe_emulator_endpoint,
    is_floci_e2e_enabled,
    is_local_emulator_endpoint,
    resolve_emulator_endpoint_url,
)
from tools.live_e2e.runner import (
    _CI_ENVIRONMENT_SIGNALS,
    ACCOUNT_CONFIRMATION,
    ZONE_CONFIRMATION,
    LiveE2ERunner,
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("# test\n", encoding="utf-8")
    (root / "cdk.json").write_text("{}\n", encoding="utf-8")
    (root / "openemr_ecs").mkdir()
    return root


@pytest.mark.parametrize(
    ("endpoint", "expected"),
    (
        ("http://127.0.0.1:4566", True),
        ("http://localhost:4566", True),
        ("http://floci:4566", True),
        ("http://10.0.0.5:4566", True),
        ("https://sts.us-east-1.amazonaws.com", False),
        ("https://example.com:4566", False),
        ("not-a-url", False),
    ),
)
def test_local_emulator_endpoint_detection(endpoint: str, expected: bool) -> None:
    assert is_local_emulator_endpoint(endpoint) is expected


def test_resolve_emulator_endpoint_prefers_project_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENEMR_AWS_ENDPOINT_URL", "http://127.0.0.1:4566")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9999")
    assert resolve_emulator_endpoint_url() == "http://127.0.0.1:4566"


def test_floci_mode_requires_local_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(FLOCI_E2E_ENVIRONMENT, "1")
    monkeypatch.delenv("OPENEMR_AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    with pytest.raises(ToolError, match="requires"):
        is_floci_e2e_enabled(None)
    with pytest.raises(ToolError, match="refuses"):
        assert_safe_emulator_endpoint("https://sts.us-east-1.amazonaws.com")


@pytest.mark.parametrize("signal", _CI_ENVIRONMENT_SIGNALS)
def test_floci_mode_allows_ci_without_calling_real_aws(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal: str,
) -> None:
    monkeypatch.setenv(signal, "true")
    monkeypatch.setenv(FLOCI_E2E_ENVIRONMENT, "1")
    monkeypatch.setenv("OPENEMR_AWS_ENDPOINT_URL", "http://127.0.0.1:4566")

    class BoomAdapter:
        def __init__(self, **kwargs: object) -> None:
            self.kwargs = kwargs

        def preflight(self, **_kwargs: object) -> None:
            raise AssertionError("preflight should not run before local failures are mocked")

    runner = LiveE2ERunner(root=_root(tmp_path), aws_factory=BoomAdapter)
    # Local git/tool checks still run; prove the CI gate itself is bypassed.
    LiveE2ERunner._assert_local_execution(require_tty=False)

    adapter = runner._aws_adapter(region="us-east-1", profile_name=None)
    assert isinstance(adapter, BoomAdapter)
    assert adapter.kwargs["endpoint_url"] == "http://127.0.0.1:4566"
    assert adapter.kwargs["emulated"] is True


def test_ci_without_floci_still_blocks(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    monkeypatch.delenv(FLOCI_E2E_ENVIRONMENT, raising=False)
    runner = LiveE2ERunner(
        root=_root(tmp_path),
        aws_factory=lambda **_: pytest.fail("AWS must not be called"),
    )
    with pytest.raises(ToolError, match="disabled in CI"):
        runner.preflight(
            approved_account="123456789012",
            region="us-east-1",
            route53_domain="e2e.example.org",
            allowed_ipv4_cidr="8.8.8.8/32",
            profile="default",
            aws_profile=None,
            cdk_command="cdk",
            bootstrap_stack_name="CDKToolkit",
            confirm_dedicated_zone=ZONE_CONFIRMATION,
            confirm_non_production_account=ACCOUNT_CONFIRMATION,
            require_tty=False,
        )


def test_emulated_quota_probes_skip_service_quotas() -> None:
    from tools.live_e2e.aws import LiveE2EAws

    class Session:
        def client(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("service-quotas must not be contacted in emulated mode")

    adapter = LiveE2EAws(
        region="us-east-1",
        session=Session(),
        endpoint_url="http://127.0.0.1:4566",
        emulated=True,
    )
    checks = adapter._quota_probes()
    assert checks
    assert all(check.status == "pass" and "floci-emulated" in check.detail for check in checks)


def test_emulated_permission_probes_tolerate_unknown_operations() -> None:
    from botocore.exceptions import ClientError

    from tools.live_e2e.aws import LiveE2EAws

    class FakeClient:
        def list_stacks(self, **_kwargs: object) -> dict[str, list[object]]:
            return {"StackSummaries": []}

        def describe_vpcs(self, **_kwargs: object) -> dict[str, list[object]]:
            return {"Vpcs": []}

        def list_clusters(self, **_kwargs: object) -> dict[str, list[object]]:
            return {"clusterArns": []}

        def describe_db_clusters(self, **_kwargs: object) -> dict[str, list[object]]:
            return {"DBClusters": []}

        def describe_file_systems(self, **_kwargs: object) -> dict[str, list[object]]:
            raise ClientError(
                {
                    "Error": {
                        "Code": "UnknownOperationException",
                        "Message": "Unknown operation: GET /2015-02-01/file-systems",
                    }
                },
                "DescribeFileSystems",
            )

        def list_aliases(self, **_kwargs: object) -> dict[str, list[object]]:
            return {"Aliases": []}

        def list_backup_vaults(self, **_kwargs: object) -> dict[str, list[object]]:
            return {"BackupVaultList": []}

        def list_web_acls(self, **_kwargs: object) -> dict[str, list[object]]:
            return {"WebACLs": []}

    class Session:
        def client(self, *_args: object, **_kwargs: object) -> FakeClient:
            return FakeClient()

    adapter = LiveE2EAws(
        region="us-east-1",
        session=Session(),
        endpoint_url="http://127.0.0.1:4566",
        emulated=True,
    )
    checks = {check.name: check.detail for check in adapter._permission_probes()}
    assert "floci-emulated" in checks["efs-read"]
    assert checks["cloudformation-read"] == "API probe succeeded"
