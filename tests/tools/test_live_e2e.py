"""Tests for guarded live E2E policy, timing, and reporting."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import aws_cdk as cdk
import pytest

from app import (
    LIVE_E2E_RUNNER_ENVIRONMENT,
    assert_live_e2e_runner_context,
    bind_live_e2e_availability_zone_context,
    stack_id_for_live_e2e,
)
from tools._shared import CommandResult, ToolError, fingerprint, hash_account_id
from tools.live_e2e import docker_proxy
from tools.live_e2e.aws import LiveE2EAws, _iam_principal_arn
from tools.live_e2e.cli import build_parser
from tools.live_e2e.models import SCHEMA_VERSION, CheckResult, PhaseTiming, ResidualResource, RunResult
from tools.live_e2e.report import (
    append_result,
    empty_history,
    load_history,
    render_markdown,
    update_cleanup_result,
)
from tools.live_e2e.runner import (
    ACCOUNT_CONFIRMATION,
    APPROVAL_ENVIRONMENT,
    CREATE_CONFIRMATION,
    DESTROY_CONFIRMATION,
    KEEP_CONFIRMATION,
    ZONE_CONFIRMATION,
    LiveE2ERunner,
    _assembly_versions,
    _directory_fingerprint,
    _docker_build_duration,
    _repository_slug,
    deployment_contexts,
    stack_name,
    validate_inputs,
)


def _result(run_id: str = "e2e-20260731t120000z-abcd1234") -> RunResult:
    return RunResult(
        schema_version=SCHEMA_VERSION,
        run_id=run_id,
        started_at="2026-07-31T12:00:00Z",
        finished_at="2026-07-31T12:20:00Z",
        git_commit="a" * 40,
        branch="feature/live-e2e",
        repository="openemr/openemr-on-ecs",
        account_hash="sha256:abcdef012345",
        region="us-east-1",
        safe_stack_id="sha256:012345abcdef",
        profile="default",
        configuration_fingerprint="sha256:0123456789abcdef",
        bootstrap_state="ready-v27",
        python_version="3.14.0",
        node_version="v24.1.0",
        cdk_cli_version="2.1029.0",
        cdk_library_version="2.263.0",
        openemr_version="8.2.0",
        aurora_version="8.0.mysql_aurora.3.12.0",
        test_runner_version="1.0.0",
        status="passed",
        stack_status="CREATE_COMPLETE",
        cleanup_status="complete",
        failure_phase=None,
        import_duration_seconds=None,
        phases=(
            PhaseTiming("cdk-deploy", 600.1, "local-monotonic-clock"),
            PhaseTiming("application-https-ready", 120.2, "local-monotonic-clock-with-https-probes"),
            PhaseTiming("total", 1200.3, "local-monotonic-clock"),
        ),
        checks=(CheckResult("application-https", "pass", "HTTPS returned OpenEMR"),),
    )


def _root(path: Path) -> Path:
    (path / "cdk.json").write_text("{}\n", encoding="utf-8")
    (path / "openemr_ecs").mkdir()
    return path


def test_empty_report_never_claims_an_unmeasured_timing() -> None:
    report = render_markdown(empty_history())
    assert "No live E2E deployment has been approved or measured yet." in report
    assert "Median" not in report
    assert "0m" not in report


def test_result_append_is_idempotent_and_report_is_deterministic(tmp_path: Path) -> None:
    history_path = tmp_path / "history.json"
    report_path = tmp_path / "report.md"
    result = _result()

    append_result(history_path, report_path, result)
    first = report_path.read_bytes()
    append_result(history_path, report_path, result)

    assert report_path.read_bytes() == first
    history = load_history(history_path)
    assert len(history["runs"]) == 1
    assert "20m 00s" in first.decode("utf-8")
    assert "## Latest successful measurement" in first.decode("utf-8")
    assert "## Profile statistics" in first.decode("utf-8")
    assert "## Methodology" in first.decode("utf-8")
    assert "## Comparability caveats" in first.decode("utf-8")
    assert "e2e-results/history.json" in first.decode("utf-8")
    assert "123456789012" not in history_path.read_text(encoding="utf-8")


def test_history_rejects_raw_accounts_and_credential_like_values(tmp_path: Path) -> None:
    history_path = tmp_path / "history.json"
    report_path = tmp_path / "report.md"

    with pytest.raises(ToolError, match="identifier"):
        append_result(
            history_path,
            report_path,
            replace(_result(), notes=("password=must-not-leak",)),
        )
    with pytest.raises(ToolError, match="account"):
        append_result(
            history_path,
            report_path,
            replace(_result(), account_hash="123456789012"),
        )
    with pytest.raises(ToolError, match="host"):
        append_result(
            history_path,
            report_path,
            replace(_result(), notes=("application at openemr.e2e.example.org",)),
        )


def test_cleanup_retry_updates_existing_history_and_regenerates_report(
    tmp_path: Path,
) -> None:
    history_path = tmp_path / "history.json"
    report_path = tmp_path / "report.md"
    append_result(
        history_path,
        report_path,
        replace(
            _result(),
            status="failed",
            cleanup_status="retained-on-failure",
            failure_phase="cleanup",
        ),
    )

    updated = update_cleanup_result(
        history_path,
        report_path,
        run_id=_result().run_id,
        cleanup_status="complete",
        residuals=(),
        phase=PhaseTiming(
            "cleanup-retry",
            42.0,
            "local-monotonic-clock",
        ),
        finished_at="2026-07-31T13:00:00Z",
    )

    assert updated
    run = load_history(history_path)["runs"][0]
    assert run["status"] == "passed"
    assert run["cleanup_status"] == "complete"
    assert run["failure_phase"] is None
    assert any(phase["name"] == "cleanup-retry" for phase in run["phases"])


def test_failed_cleanup_retry_never_promotes_run_to_passed(tmp_path: Path) -> None:
    history_path = tmp_path / "history.json"
    report_path = tmp_path / "report.md"
    append_result(
        history_path,
        report_path,
        replace(
            _result(),
            status="failed",
            cleanup_status="failed",
            failure_phase="cleanup",
        ),
    )

    update_cleanup_result(
        history_path,
        report_path,
        run_id=_result().run_id,
        cleanup_status="failed",
        residuals=(ResidualResource("s3", "sha256:abcdef123456", "unexpected-residual"),),
        phase=PhaseTiming("cleanup-retry", 1.0, "local-monotonic-clock"),
        finished_at="2026-07-31T13:00:00Z",
    )

    run = load_history(history_path)["runs"][0]
    assert run["status"] == "failed"
    assert run["failure_phase"] == "cleanup"
    assert "Latest successful measurement" in report_path.read_text(encoding="utf-8")


def test_contexts_are_isolated_and_profiles_are_explicit() -> None:
    default = deployment_contexts(
        run_id="e2e-valid-run",
        account_id="123456789012",
        region="us-east-1",
        availability_zones=("us-east-1a", "us-east-1b"),
        route53_domain="test.example.org",
        hosted_zone_id="ZTEST123",
        allowed_ipv4_cidr="8.8.8.8/32",
        profile="default",
    )
    alternate = deployment_contexts(
        run_id="e2e-valid-run",
        account_id="123456789012",
        region="us-east-1",
        availability_zones=("us-east-1a", "us-east-1b"),
        route53_domain="test.example.org",
        hosted_zone_id="ZTEST123",
        allowed_ipv4_cidr="8.8.8.8/32",
        profile="api-enabled",
    )

    assert default["live_e2e_run_id"] == "e2e-valid-run"
    assert "certificate_arn" not in default
    assert default["rds_deletion_protection"] == "false"
    assert default["disable_rds_deletion_protection_on_destroy"] == "true"
    assert default["security_group_ip_range_ipv4"] == "8.8.8.8/32"
    assert default["activate_openemr_apis"] == "false"
    assert default["enable_long_term_cloudtrail_monitoring"] == "false"
    assert default["enable_global_accelerator"] == "false"
    assert default["create_serverless_analytics_environment"] == "false"
    assert default["route53_hosted_zone_id"] == "ZTEST123"
    assert default["openemr_import_target"] == "false"
    assert default["openemr_service_fargate_minimum_capacity"] == "1"
    assert default["openemr_service_fargate_maximum_capacity"] == "1"
    assert default["live_e2e_availability_zones"] == '["us-east-1a","us-east-1b"]'
    assert alternate["activate_openemr_apis"] == "true"
    assert alternate["enable_data_api"] == "true"
    assert stack_name("e2e-valid-run").startswith("OpenemrE2E-")
    assert stack_id_for_live_e2e(None) == "OpenemrEcsStack"
    assert stack_id_for_live_e2e("e2e-valid-run") == stack_name("e2e-valid-run")
    with pytest.raises(ValueError, match="live_e2e_run_id"):
        stack_id_for_live_e2e("INVALID")
    assert _repository_slug("git@github.com:openemr/openemr-on-ecs.git") == "openemr/openemr-on-ecs"
    assert _repository_slug("https://github.com/openemr/openemr-on-ecs.git") == "openemr/openemr-on-ecs"
    assert (
        _iam_principal_arn("arn:aws:sts::123456789012:assumed-role/team/platform/deployer/session")
        == "arn:aws:iam::123456789012:role/team/platform/deployer"
    )


def test_plan_json_and_noninteractive_modes_are_explicit_cli_options() -> None:
    args = build_parser().parse_args(
        [
            "plan",
            "--approved-account",
            "123456789012",
            "--region",
            "us-east-1",
            "--route53-domain",
            "e2e.example.org",
            "--allowed-ipv4-cidr",
            "8.8.8.8/32",
            "--confirm-dedicated-zone",
            ZONE_CONFIRMATION,
            "--confirm-non-production-account",
            ACCOUNT_CONFIRMATION,
            "--noninteractive",
            "--json",
        ]
    )
    assert args.command == "plan"
    assert args.noninteractive
    assert args.json


def test_synth_command_is_lookup_free_and_uses_current_python(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _root(tmp_path)
    run_dir = root / ".live-e2e" / "runs" / "e2e-command-test"
    run_dir.mkdir(parents=True)
    captured: dict[str, Any] = {}

    def fake_run_command(argv: list[str], **kwargs: Any) -> CommandResult:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        return CommandResult(tuple(argv), 0, "", "", 0.1)

    monkeypatch.setattr("tools.live_e2e.runner.run_command", fake_run_command)
    LiveE2ERunner(root=root)._cdk_command(
        cdk_command="/opt/cdk",
        operation="synth",
        run_id="e2e-command-test",
        contexts={"live_e2e_run_id": "e2e-command-test"},
        run_dir=run_dir,
        aws_profile=None,
        account_id="123456789012",
        region="us-east-1",
        timeout_seconds=60,
    )

    argv = captured["argv"]
    assert argv[:3] == ["/opt/cdk", "synth", stack_name("e2e-command-test")]
    assert "--no-lookups" in argv
    assert "--app" in argv
    assert sys.executable in argv[argv.index("--app") + 1]
    assert captured["kwargs"]["env"]["OPENEMR_LIVE_E2E_RUNNER_RUN_ID"] == "e2e-command-test"


def test_cloud_assembly_provides_exact_deployment_versions(tmp_path: Path) -> None:
    stack = stack_name("e2e-version-test")
    (tmp_path / "manifest.json").write_text(
        json.dumps({"artifacts": {stack: {"properties": {"templateFile": "stack.template.json"}}}}),
        encoding="utf-8",
    )
    (tmp_path / "stack.template.json").write_text(
        json.dumps(
            {
                "Outputs": {"OpenEMRVersion": {"Value": "8.2.0"}},
                "Resources": {
                    "Database": {
                        "Type": "AWS::RDS::DBCluster",
                        "Properties": {"EngineVersion": "8.0.mysql_aurora.3.12.0"},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert _assembly_versions(tmp_path, stack) == {
        "openemr_version": "8.2.0",
        "aurora_version": "8.0.mysql_aurora.3.12.0",
    }


def test_docker_build_timing_is_structured_and_bounded(tmp_path: Path) -> None:
    timing = tmp_path / "docker.jsonl"
    timing.write_text(
        "\n".join(
            (
                json.dumps(
                    {
                        "schema_version": 1,
                        "category": "build",
                        "duration_seconds": 2.25,
                        "returncode": 0,
                    }
                ),
                json.dumps(
                    {
                        "schema_version": 1,
                        "category": "publish",
                        "duration_seconds": 1.5,
                        "returncode": 0,
                    }
                ),
            )
        ),
        encoding="utf-8",
    )
    assert _docker_build_duration(timing) == 2.25
    timing.write_text('{"category":"build","duration_seconds":"many"}\n', encoding="utf-8")
    with pytest.raises(ToolError, match="entry"):
        _docker_build_duration(timing)


def test_docker_proxy_never_records_forwarded_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o700)
    timing = tmp_path / "timing.jsonl"
    monkeypatch.setenv("OPENEMR_E2E_REAL_DOCKER", str(docker))
    monkeypatch.setenv("OPENEMR_E2E_DOCKER_TIMINGS", str(timing))
    monkeypatch.setattr(
        "sys.argv",
        ["docker-proxy", "login", "--password", "must-not-leak"],
    )

    assert docker_proxy.main() == 0
    content = timing.read_text(encoding="utf-8")
    assert "must-not-leak" not in content
    assert json.loads(content)["category"] == "other"


@pytest.mark.parametrize(
    ("domain", "cidr"),
    (
        ("example.org", "8.8.8.8/32"),
        ("e2e.example.org", "0.0.0.0/0"),
        ("e2e.example.org", "10.0.0.1/32"),
        ("e2e.invalid.example", "8.8.8.8/32"),
    ),
)
def test_scope_validation_rejects_shared_zones_and_unsafe_networks(domain: str, cidr: str) -> None:
    with pytest.raises(ToolError):
        validate_inputs(
            approved_account="123456789012",
            region="us-east-1",
            route53_domain=domain,
            allowed_ipv4_cidr=cidr,
            profile="default",
        )


def test_live_e2e_hosted_zone_must_have_only_delegation_records() -> None:
    class Paginator:
        def __init__(self, records: list[dict[str, str]]) -> None:
            self.records = records

        def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
            assert kwargs == {"HostedZoneId": "/hostedzone/E2E"}
            return [{"ResourceRecordSets": self.records}]

    class Route53:
        def __init__(self, records: list[dict[str, str]]) -> None:
            self.records = records

        def get_paginator(self, operation: str) -> Paginator:
            assert operation == "list_resource_record_sets"
            return Paginator(self.records)

    adapter = LiveE2EAws(region="us-east-1", session=SimpleNamespace())
    adapter._clients["route53:True"] = Route53([{"Type": "NS"}, {"Type": "SOA"}])
    adapter._assert_dedicated_zone_records({"Id": "/hostedzone/E2E"})

    adapter._clients["route53:True"] = Route53([{"Type": "NS"}, {"Type": "A"}])
    with pytest.raises(ToolError, match="existing non-delegation records"):
        adapter._assert_dedicated_zone_records({"Id": "/hostedzone/E2E"})


def test_cleanup_ownership_accepts_json_template_body(monkeypatch: pytest.MonkeyPatch) -> None:
    run_id = "e2e-owned-stack"
    stack = {"StackId": "stack-id", "Outputs": []}

    class CloudFormation:
        def get_template(self, **_: Any) -> dict[str, str]:
            return {
                "TemplateBody": json.dumps(
                    {
                        "Outputs": {
                            "LiveE2ERunId": {
                                "Value": run_id,
                            }
                        }
                    }
                )
            }

    adapter = LiveE2EAws(region="us-east-1", session=SimpleNamespace())
    adapter._clients["cloudformation:False"] = CloudFormation()
    monkeypatch.setattr(adapter, "describe_stack", lambda _: stack)

    assert adapter.assert_owned_stack("stack-id", run_id) is stack


def test_delete_complete_is_a_terminal_cleanup_success(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = LiveE2EAws(region="us-east-1", session=SimpleNamespace())
    monkeypatch.setattr(
        adapter,
        "describe_stack",
        lambda _: {"StackStatus": "DELETE_COMPLETE"},
    )
    monkeypatch.setattr("tools.live_e2e.aws.time.sleep", lambda _: pytest.fail("must not sleep"))

    adapter.wait_for_stack_deleted(
        "stack-id",
        timeout_seconds=1,
        poll_seconds=0.01,
    )


def test_live_e2e_context_requires_runner_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    run_id = "e2e-runner-guard"
    monkeypatch.delenv(LIVE_E2E_RUNNER_ENVIRONMENT, raising=False)
    with pytest.raises(ValueError, match="reserved"):
        assert_live_e2e_runner_context(run_id)

    monkeypatch.setenv(LIVE_E2E_RUNNER_ENVIRONMENT, run_id)
    assert_live_e2e_runner_context(run_id)


def test_live_e2e_zones_bind_to_cdk_provider_context() -> None:
    app = cdk.App()
    bind_live_e2e_availability_zone_context(
        app,
        live_e2e_run_id="e2e-runner-guard",
        raw_availability_zones='["us-east-1a","us-east-1b"]',
        account="123456789012",
        region="us-east-1",
    )
    assert app.node.try_get_context("availability-zones:account=123456789012:region=us-east-1") == [
        "us-east-1a",
        "us-east-1b",
    ]

    with pytest.raises(ValueError, match="reserved"):
        bind_live_e2e_availability_zone_context(
            cdk.App(),
            live_e2e_run_id=None,
            raw_availability_zones='["us-east-1a","us-east-1b"]',
            account="123456789012",
            region="us-east-1",
        )


def test_run_stays_locked_without_every_confirmation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _root(tmp_path)
    runner = LiveE2ERunner(root=root, aws_factory=lambda **_: pytest.fail("AWS must not be called"))
    run_id = "e2e-locked-run"
    preflight_dir = root / ".live-e2e" / "preflight"
    preflight_dir.mkdir(parents=True)
    preflight = preflight_dir / f"{run_id}.json"
    preflight.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "expires_at": "2099-01-01T00:00:00Z",
                "git_commit": "a" * 40,
                "branch": "feature/live-e2e",
                "repository": "openemr/openemr-on-ecs",
                "account_id": "123456789012",
                "account_hash": hash_account_id("123456789012"),
                "region": "us-east-1",
                "availability_zones": ["us-east-1a", "us-east-1b"],
                "route53_domain": "e2e.example.org",
                "hosted_zone_id": "ZTEST123",
                "allowed_ipv4_cidr": "8.8.8.8/32",
                "profile": "default",
                "cdk_command": "/usr/bin/false",
                "stack_name": stack_name(run_id),
                "context_fingerprint": "deadbeefdeadbeef",
                "assembly_fingerprint": "sha256:not-reached",
                "bootstrap_version": 27,
                "versions": {
                    "python_version": "3.14.0",
                    "node_version": "v24.1.0",
                    "cdk_cli_version": "2.1029.0",
                    "cdk_library_version": "2.263.0",
                    "openemr_version": "8.2.0",
                    "aurora_version": "8.0.mysql_aurora.3.12.0",
                },
                "resource_count": 1,
                "resource_types": {"AWS::CloudFormation::WaitConditionHandle": 1},
                "preflight_phases": [
                    {
                        "name": "preflight",
                        "duration_seconds": 1.0,
                        "source": "local-monotonic-clock",
                        "started_at": None,
                        "finished_at": None,
                    }
                ],
                "checks": [],
            }
        ),
        encoding="utf-8",
    )
    preflight.chmod(0o600)
    monkeypatch.setenv(APPROVAL_ENVIRONMENT, run_id)

    with pytest.raises(ToolError, match="confirm-create"):
        runner.run(
            preflight_path=preflight,
            approved_account="123456789012",
            confirm_create="wrong",
            confirm_destroy=DESTROY_CONFIRMATION,
            confirm_costs=True,
            require_tty=False,
        )
    assert not (root / ".live-e2e" / "runs").exists()


def test_live_e2e_local_state_root_is_owner_only_and_not_a_symlink(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir()
    root = _root(private_root)
    runner = LiveE2ERunner(root=root)

    with runner._lock():
        assert runner.local_root.stat().st_mode & 0o777 == 0o700

    linked_root_path = tmp_path / "linked"
    linked_root_path.mkdir()
    linked_root = _root(linked_root_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (linked_root / ".live-e2e").symlink_to(outside, target_is_directory=True)
    linked_runner = LiveE2ERunner(root=linked_root)

    with pytest.raises(ToolError, match="symlinked"):
        with linked_runner._lock():
            pytest.fail("symlinked state directory must never be locked")


@pytest.mark.parametrize("signal", ("CI", "GITHUB_ACTIONS", "GITLAB_CI"))
def test_ci_environment_blocks_live_actions_before_aws(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signal: str,
) -> None:
    runner = LiveE2ERunner(
        root=_root(tmp_path),
        aws_factory=lambda **_: pytest.fail("AWS must not be called"),
    )
    monkeypatch.setenv(signal, "true")
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


class _CleanupAdapter:
    def __init__(self) -> None:
        self.describe_calls = 0
        self.delete_called = False
        self.deleted = False

    def identity(self) -> dict[str, str]:
        return {
            "account_id": "123456789012",
            "account_hash": hash_account_id("123456789012"),
        }

    def describe_stack(self, _: str) -> dict[str, Any] | None:
        self.describe_calls += 1
        if self.deleted or self.describe_calls == 1:
            return None
        return {
            "StackId": "arn:aws:cloudformation:us-east-1:123456789012:stack/test/id",
            "StackStatus": "CREATE_COMPLETE",
        }

    def event_phases(self, *_: Any, **__: Any) -> tuple[PhaseTiming, ...]:
        return ()

    def validate_deployment(self, **_: Any) -> Any:
        raise ToolError("injected validation failure")

    def delete_owned_stack(self, _: str, run_id: str) -> str:
        assert run_id == "e2e-cleanup-test"
        self.delete_called = True
        return "stack-id"

    def wait_for_stack_deleted(self, *_: Any, **__: Any) -> None:
        assert self.delete_called
        self.deleted = True

    def residual_resources(self, _: str) -> tuple[Any, ...]:
        assert self.deleted
        return ()

    def bootstrap_asset_residuals(self, _: Path) -> tuple[Any, ...]:
        assert self.deleted
        return ()

    def cleanup_owned_log_groups(self, _: str, __: str) -> int:
        assert self.deleted
        return 0


class _CommandRunner(LiveE2ERunner):
    def _git_commit_and_clean(self) -> str:
        return "a" * 40

    def _cdk_command(self, **_: Any) -> CommandResult:
        return CommandResult(("cdk", "deploy"), 0, "", "", 2.5)


def _write_approved_preflight(root: Path, run_id: str) -> Path:
    contexts = deployment_contexts(
        run_id=run_id,
        account_id="123456789012",
        region="us-east-1",
        availability_zones=("us-east-1a", "us-east-1b"),
        route53_domain="e2e.example.org",
        hosted_zone_id="ZTEST123",
        allowed_ipv4_cidr="8.8.8.8/32",
        profile="default",
    )
    preflight_dir = root / ".live-e2e" / "preflight"
    run_dir = root / ".live-e2e" / "runs" / run_id
    preflight_dir.mkdir(parents=True)
    (run_dir / "cdk.out").mkdir(parents=True)
    (run_dir / "cdk.out" / "manifest.json").write_text("{}\n", encoding="utf-8")
    preflight = preflight_dir / f"{run_id}.json"
    preflight.write_text(
        json.dumps(
            {
                "schema_version": SCHEMA_VERSION,
                "run_id": run_id,
                "expires_at": "2099-01-01T00:00:00Z",
                "git_commit": "a" * 40,
                "branch": "feature/live-e2e",
                "repository": "openemr/openemr-on-ecs",
                "account_id": "123456789012",
                "account_hash": hash_account_id("123456789012"),
                "region": "us-east-1",
                "availability_zones": ["us-east-1a", "us-east-1b"],
                "route53_domain": "e2e.example.org",
                "hosted_zone_id": "ZTEST123",
                "allowed_ipv4_cidr": "8.8.8.8/32",
                "profile": "default",
                "aws_profile": None,
                "cdk_command": "/usr/bin/false",
                "stack_name": stack_name(run_id),
                "context_fingerprint": fingerprint(contexts),
                "assembly_fingerprint": _directory_fingerprint(run_dir / "cdk.out"),
                "bootstrap_version": 27,
                "versions": {
                    "python_version": "3.14.0",
                    "node_version": "v24.1.0",
                    "cdk_cli_version": "2.1029.0",
                    "cdk_library_version": "2.263.0",
                    "openemr_version": "8.2.0",
                    "aurora_version": "8.0.mysql_aurora.3.12.0",
                },
                "resource_count": 1,
                "resource_types": {"AWS::CloudFormation::WaitConditionHandle": 1},
                "preflight_phases": [
                    {
                        "name": "preflight",
                        "duration_seconds": 1.0,
                        "source": "local-monotonic-clock",
                        "started_at": None,
                        "finished_at": None,
                    }
                ],
                "checks": [],
            }
        ),
        encoding="utf-8",
    )
    preflight.chmod(0o600)
    return preflight


def test_validation_failure_still_deletes_owned_stack_and_records_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)
    adapter = _CleanupAdapter()
    runner = _CommandRunner(root=root, aws_factory=lambda **_: adapter)
    run_id = "e2e-cleanup-test"
    preflight = _write_approved_preflight(root, run_id)
    monkeypatch.setenv(APPROVAL_ENVIRONMENT, run_id)

    result = runner.run(
        preflight_path=preflight,
        approved_account="123456789012",
        confirm_create=CREATE_CONFIRMATION,
        confirm_destroy=DESTROY_CONFIRMATION,
        confirm_costs=True,
        require_tty=False,
        poll_seconds=0.001,
    )

    assert result.status == "failed"
    assert result.cleanup_status == "complete"
    assert adapter.delete_called
    assert adapter.deleted
    assert load_history(root / "e2e-results" / "history.json")["runs"][0]["run_id"] == run_id
    raw_result = root / ".live-e2e" / "runs" / run_id / "result.json"
    assert raw_result.is_file()
    assert raw_result.stat().st_mode & 0o077 == 0


class _RetentionAdapter(_CleanupAdapter):
    def assert_owned_stack(self, stack_id: str, run_id: str) -> dict[str, Any]:
        assert stack_id.startswith("arn:aws:cloudformation:")
        assert run_id == "e2e-retain-test"
        return {"StackId": stack_id}

    def delete_owned_stack(self, _: str, run_id: str) -> str:
        pytest.fail(f"retained run {run_id} must not be deleted")

    def wait_for_stack_deleted(self, *_: Any, **__: Any) -> None:
        pytest.fail("retained run must not wait for deletion")

    def residual_resources(self, _: str) -> tuple[Any, ...]:
        return ()

    def bootstrap_asset_residuals(self, _: Path) -> tuple[Any, ...]:
        return ()


def test_explicit_keep_on_failure_preserves_owned_stack(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _root(tmp_path)
    adapter = _RetentionAdapter()
    runner = _CommandRunner(root=root, aws_factory=lambda **_: adapter)
    run_id = "e2e-retain-test"
    preflight = _write_approved_preflight(root, run_id)
    monkeypatch.setenv(APPROVAL_ENVIRONMENT, run_id)

    result = runner.run(
        preflight_path=preflight,
        approved_account="123456789012",
        confirm_create=CREATE_CONFIRMATION,
        confirm_destroy=DESTROY_CONFIRMATION,
        confirm_costs=True,
        keep_on_failure=True,
        confirm_keep_on_failure=KEEP_CONFIRMATION,
        require_tty=False,
        poll_seconds=0.001,
    )

    assert result.status == "failed"
    assert result.cleanup_status == "retained-on-failure"
    assert not adapter.delete_called
    assert not adapter.deleted


def test_workflows_never_invoke_live_e2e() -> None:
    root = Path(__file__).resolve().parents[2]
    workflows = "\n".join(path.read_text(encoding="utf-8") for path in (root / ".github" / "workflows").glob("*.yml"))
    assert "tools.live_e2e preflight" not in workflows
    assert "tools.live_e2e run" not in workflows
    assert "tools.live_e2e cleanup" not in workflows


class _AssetS3:
    def head_object(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {"Bucket": "bootstrap-assets", "Key": "asset.zip"}
        return {}


class _AssetEcr:
    def describe_images(self, **kwargs: Any) -> dict[str, Any]:
        assert kwargs == {
            "repositoryName": "bootstrap-images",
            "imageIds": [{"imageTag": "image-hash"}],
        }
        return {"imageDetails": [{}]}


class _AssetSession:
    def client(self, service: str, **_: Any) -> Any:
        return {"s3": _AssetS3(), "ecr": _AssetEcr()}[service]


def test_bootstrap_asset_inventory_reports_shared_retained_assets(tmp_path: Path) -> None:
    (tmp_path / "stack.assets.json").write_text(
        json.dumps(
            {
                "files": {
                    "file-hash": {
                        "destinations": {
                            "current": {
                                "bucketName": "bootstrap-assets",
                                "objectKey": "asset.zip",
                                "region": "us-east-1",
                            }
                        }
                    }
                },
                "dockerImages": {
                    "image-hash": {
                        "destinations": {
                            "current": {
                                "repositoryName": "bootstrap-images",
                                "imageTag": "image-hash",
                                "region": "us-east-1",
                            }
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    adapter = LiveE2EAws(region="us-east-1", session=_AssetSession())

    residuals = adapter.bootstrap_asset_residuals(tmp_path)

    assert {item.resource_type for item in residuals} == {
        "cdk-bootstrap-ecr-asset",
        "cdk-bootstrap-s3-asset",
    }
    assert {item.disposition for item in residuals} == {"shared-content-addressed-asset"}
    assert all(item.identifier_hash.startswith("sha256:") for item in residuals)


class _LogPaginator:
    def __init__(self, matching_name: str) -> None:
        self.matching_name = matching_name

    def paginate(self, **_: Any) -> list[dict[str, Any]]:
        return [
            {
                "logGroups": [
                    {"logGroupName": self.matching_name},
                    {"logGroupName": "/aws/lambda/unrelated"},
                ]
            }
        ]


class _Logs:
    def __init__(self, matching_name: str) -> None:
        self.deleted: list[str] = []
        self.matching_name = matching_name

    def get_paginator(self, operation: str) -> _LogPaginator:
        assert operation == "describe_log_groups"
        return _LogPaginator(self.matching_name)

    def delete_log_group(self, *, logGroupName: str) -> None:
        self.deleted.append(logGroupName)


class _LogSession:
    def __init__(self, logs: _Logs) -> None:
        self.logs = logs

    def client(self, service: str, **_: Any) -> _Logs:
        assert service == "logs"
        return self.logs


def test_orphan_log_cleanup_is_bounded_to_exact_e2e_stack_prefix() -> None:
    name = stack_name("e2e-log-test")
    matching_log = f"/aws/lambda/{name}-CustomA"
    logs = _Logs(matching_log)
    adapter = LiveE2EAws(region="us-east-1", session=_LogSession(logs))

    deleted = adapter.cleanup_owned_log_groups(
        name,
        "e2e-log-test",
    )

    assert deleted == 1
    assert logs.deleted == [matching_log]
    with pytest.raises(ToolError, match="outside"):
        adapter.cleanup_owned_log_groups("OpenemrEcsStack", "e2e-log-test")


class _CloudFormation:
    def describe_stack_events(self, **_: Any) -> dict[str, Any]:
        def stamp(minute: int) -> datetime:
            return datetime(2026, 7, 31, 12, minute, tzinfo=timezone.utc)

        return {
            "StackEvents": [
                {
                    "ResourceType": "AWS::CloudFormation::Stack",
                    "ResourceStatus": "CREATE_IN_PROGRESS",
                    "Timestamp": stamp(0),
                },
                {
                    "ResourceType": "AWS::RDS::DBCluster",
                    "ResourceStatus": "CREATE_IN_PROGRESS",
                    "Timestamp": stamp(2),
                },
                {
                    "ResourceType": "AWS::RDS::DBCluster",
                    "ResourceStatus": "CREATE_COMPLETE",
                    "Timestamp": stamp(12),
                },
                {
                    "ResourceType": "AWS::CloudFormation::Stack",
                    "ResourceStatus": "CREATE_COMPLETE",
                    "Timestamp": stamp(15),
                },
            ]
        }


class _Session:
    def client(self, service: str, **_: Any) -> Any:
        assert service == "cloudformation"
        return _CloudFormation()


def test_phase_timing_uses_cloudformation_api_timestamps() -> None:
    adapter = LiveE2EAws(region="us-east-1", session=_Session())
    phases = {phase.name: phase for phase in adapter.event_phases("stack-id", operation="CREATE")}

    assert phases["cloudformation-deployment"].duration_seconds == 900
    assert phases["aurora-provisioning"].duration_seconds == 600
    assert all(phase.source == "cloudformation-events-api" for phase in phases.values())


class _Waiter:
    def wait(self, **_: Any) -> None:
        return None


class _ValidationEcs:
    def get_waiter(self, name: str) -> _Waiter:
        assert name == "services_stable"
        return _Waiter()

    def describe_services(self, **_: Any) -> dict[str, Any]:
        return {
            "services": [
                {
                    "runningCount": 2,
                    "desiredCount": 2,
                    "deployments": [{"rolloutState": "COMPLETED"}],
                    "events": [],
                }
            ]
        }

    def list_tasks(self, **_: Any) -> dict[str, Any]:
        return {"taskArns": ["task-1", "task-2"]}

    def describe_tasks(self, **_: Any) -> dict[str, Any]:
        task = {
            "lastStatus": "RUNNING",
            "healthStatus": "HEALTHY",
            "containers": [{"lastStatus": "RUNNING", "healthStatus": "HEALTHY"}],
        }
        return {"tasks": [task, task]}


class _ValidationElbv2:
    def describe_target_health(self, **_: Any) -> dict[str, Any]:
        return {
            "TargetHealthDescriptions": [
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "healthy"}},
            ]
        }


class _ValidationEfs:
    def describe_file_systems(self, **_: Any) -> dict[str, Any]:
        return {"FileSystems": [{"LifeCycleState": "available"}]}


class _ValidationRds:
    def describe_db_clusters(self, **_: Any) -> dict[str, Any]:
        return {"DBClusters": [{"Status": "available"}]}


class _ValidationCache:
    def describe_serverless_caches(self, **_: Any) -> dict[str, Any]:
        return {"ServerlessCaches": [{"Status": "available"}]}


class _ValidationWaf:
    def get_web_acl_for_resource(self, **_: Any) -> dict[str, Any]:
        return {"WebACL": {"Name": "test"}}


class _ValidationLogs:
    def filter_log_events(self, **_: Any) -> dict[str, Any]:
        return {"events": [{"message": "OpenEMR startup complete"}]}


class _ValidationSession:
    def __init__(self) -> None:
        self.clients = {
            "ecs": _ValidationEcs(),
            "elbv2": _ValidationElbv2(),
            "efs": _ValidationEfs(),
            "rds": _ValidationRds(),
            "elasticache": _ValidationCache(),
            "wafv2": _ValidationWaf(),
            "logs": _ValidationLogs(),
        }

    def client(self, service: str, **_: Any) -> Any:
        return self.clients[service]


class _ValidationAdapter(LiveE2EAws):
    def __init__(self) -> None:
        super().__init__(region="us-east-1", session=_ValidationSession())

    def assert_owned_stack(self, _: str, run_id: str) -> dict[str, Any]:
        assert run_id == "e2e-validation"
        return {
            "StackId": "stack-id",
            "StackStatus": "CREATE_COMPLETE",
            "CreationTime": datetime(2026, 7, 31, 12, 0, tzinfo=timezone.utc),
            "Outputs": [
                {"OutputKey": "ECSClusterName", "OutputValue": "cluster"},
                {"OutputKey": "ECSServiceName", "OutputValue": "service"},
                {"OutputKey": "EFSSitesFileSystemId", "OutputValue": "fs-sites"},
                {"OutputKey": "EFSSSLFileSystemId", "OutputValue": "fs-ssl"},
                {
                    "OutputKey": "DatabaseClusterArn",
                    "OutputValue": "arn:aws:rds:us-east-1:111122223333:cluster:test",
                },
                {
                    "OutputKey": "ApplicationURL",
                    "OutputValue": "https://openemr.test.example",
                },
                {"OutputKey": "LogGroupName", "OutputValue": "/aws/ecs/test"},
            ],
        }

    def _stack_resources(self, _: str) -> list[dict[str, Any]]:
        return [
            {"ResourceType": "AWS::ECS::Cluster", "ResourceStatus": "CREATE_COMPLETE"},
            {"ResourceType": "AWS::ECS::Service", "ResourceStatus": "CREATE_COMPLETE"},
            {"ResourceType": "AWS::EFS::FileSystem", "ResourceStatus": "CREATE_COMPLETE"},
            {
                "ResourceType": "AWS::ElastiCache::ServerlessCache",
                "ResourceStatus": "CREATE_COMPLETE",
                "PhysicalResourceId": "cache",
            },
            {
                "ResourceType": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "ResourceStatus": "CREATE_COMPLETE",
                "PhysicalResourceId": "arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/test",
            },
            {
                "ResourceType": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "ResourceStatus": "CREATE_COMPLETE",
                "PhysicalResourceId": "target-group",
            },
            {"ResourceType": "AWS::RDS::DBCluster", "ResourceStatus": "CREATE_COMPLETE"},
            {
                "ResourceType": "AWS::WAFv2::WebACLAssociation",
                "ResourceStatus": "CREATE_COMPLETE",
            },
        ]


def test_deployment_validation_checks_health_logs_waf_and_smoke(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = SimpleNamespace(
        status_code=200,
        text="<title>OpenEMR</title>",
        elapsed=SimpleNamespace(total_seconds=lambda: 0.05),
    )
    monkeypatch.setattr(
        "tools.live_e2e.aws.requests.get",
        lambda *_args, **_kwargs: response,
    )

    checks, timings = _ValidationAdapter().validate_deployment(
        stack_name_or_id="stack-id",
        run_id="e2e-validation",
        https_timeout_seconds=1,
        poll_seconds=0.001,
    )

    check_names = {check.name for check in checks}
    assert {
        "ecs-task-health",
        "load-balancer-targets",
        "elasticache-serverless",
        "waf-association",
        "startup-logs",
        "application-smoke",
    }.issubset(check_names)
    timing_names = {timing.name for timing in timings}
    assert {
        "ecs-steady-state-validation",
        "aurora-availability-validation",
        "elasticache-availability-validation",
        "http-readiness",
        "application-smoke-test",
    }.issubset(timing_names)
