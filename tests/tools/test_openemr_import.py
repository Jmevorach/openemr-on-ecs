"""Tests for defensive OpenEMR import inspection and planning."""

from __future__ import annotations

import argparse
import gzip
import io
import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools._shared import ToolError
from tools.openemr_import import cli
from tools.openemr_import.aws import AwsImportError
from tools.openemr_import.cli import main
from tools.openemr_import.inspect import inspect_source
from tools.openemr_import.models import ArchiveLimits
from tools.openemr_import.plan import create_plan, plan_from_dict


def _add_bytes(
    archive: tarfile.TarFile,
    name: str,
    content: bytes,
    *,
    mode: int = 0o600,
) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = mode
    archive.addfile(member, io.BytesIO(content))


def _sql_dump(patient_marker: bytes = b"private-patient-name") -> bytes:
    return (
        b"-- MySQL dump 10.13\n"
        b"CREATE TABLE `patient_data` (`id` bigint, `name` text);\n"
        b"INSERT INTO `patient_data` VALUES (1,'" + patient_marker + b"');\n"
    )


def _sites_archive(
    *,
    version: str = "8.2.0",
    include_keys: bool = True,
    include_version: bool = True,
    executable_document: bool = False,
    second_site: bool = False,
) -> bytes:
    major, minor, patch = version.split(".")
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        if include_version:
            _add_bytes(
                archive,
                "version.php",
                (
                    "<?php\n"
                    f"$v_major = '{major}';\n"
                    f"$v_minor = '{minor}';\n"
                    f"$v_patch = '{patch}';\n"
                    "$v_tag = '';\n"
                    "$v_realpatch = '0';\n"
                ).encode(),
            )
        _add_bytes(archive, "sites/default/sqlconf.php", b"<?php secret ?>")
        _add_bytes(
            archive,
            "sites/default/config.php",
            b"<?php // official application configuration ?>",
        )
        _add_bytes(
            archive,
            "sites/default/documents/1/patient.pdf",
            b"private-document-content",
        )
        if include_keys:
            _add_bytes(
                archive,
                "sites/default/documents/logs_and_misc/methods/sixa",
                b"key-a",
            )
            _add_bytes(
                archive,
                "sites/default/documents/logs_and_misc/methods/sixb",
                b"key-b",
            )
        if executable_document:
            _add_bytes(
                archive,
                "sites/default/documents/upload.php",
                b"<?php echo 'unsafe';",
            )
        if second_site:
            _add_bytes(archive, "sites/other/sqlconf.php", b"<?php ?>")
            _add_bytes(archive, "sites/other/documents/file.pdf", b"other")
            _add_bytes(
                archive,
                "sites/other/documents/logs_and_misc/methods/sixa",
                b"a",
            )
            _add_bytes(
                archive,
                "sites/other/documents/logs_and_misc/methods/sixb",
                b"b",
            )
    return output.getvalue()


def _native_backup(
    path: Path,
    *,
    sites: bytes | None = None,
    patient_marker: bytes = b"private-patient-name",
) -> Path:
    sql = gzip.compress(_sql_dump(patient_marker))
    with tarfile.open(path, mode="w") as archive:
        _add_bytes(archive, "openemr.sql.gz", sql)
        _add_bytes(archive, "openemr.tar.gz", sites or _sites_archive())
        _add_bytes(archive, "backup-metadata.txt", b"ignored")
    return path


def test_native_backup_inspection_is_aggregate_and_plan_is_executable(
    tmp_path: Path,
) -> None:
    source = _native_backup(tmp_path / "native-backup.tar")

    inspection = inspect_source(source)
    rendered = json.dumps(inspection.to_dict())
    plan = create_plan(inspection, generated_at="2026-07-31T00:00:00Z")

    assert inspection.source_kind == "native-openemr-backup"
    assert inspection.source_openemr_version == "8.2.0"
    assert inspection.database_type == "mysql"
    assert inspection.sites[0].document_count == 3
    assert inspection.ignored_application_file_count >= 1
    assert not inspection.custom_code_detected
    assert "private-patient-name" not in rendered
    assert "private-document-content" not in rendered
    assert plan.execution_allowed
    assert plan.source_kind == inspection.source_kind
    assert plan.checksums == inspection.checksums
    assert plan_from_dict(plan.to_dict()) == plan


@pytest.mark.parametrize(
    ("sites", "expected"),
    [
        (
            _sites_archive(version="8.1.0"),
            "same-version source",
        ),
        (
            _sites_archive(include_keys=False),
            "encryption key",
        ),
        (
            _sites_archive(second_site=True),
            "exactly one site",
        ),
        (
            _sites_archive(executable_document=True),
            "Custom executable code",
        ),
    ],
    ids=("version-mismatch", "missing-keys", "multisite", "custom-code"),
)
def test_conservative_plan_blocks_unsupported_sources(
    tmp_path: Path,
    sites: bytes,
    expected: str,
) -> None:
    inspection = inspect_source(_native_backup(tmp_path / "backup.tar", sites=sites))

    plan = create_plan(inspection)

    assert not plan.execution_allowed
    assert expected.lower() in " ".join(plan.blockers).lower()


def test_directory_source_is_inspectable_but_not_executable(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "openemr.sql.gz").write_bytes(gzip.compress(_sql_dump()))
    (source / "openemr.tar.gz").write_bytes(_sites_archive())

    inspection = inspect_source(source)
    plan = create_plan(inspection)

    assert inspection.source_kind == "sql-and-sites"
    assert not plan.execution_allowed
    assert "inspection-only" in " ".join(plan.blockers)


def test_operator_declared_version_cannot_authorize_native_execution(
    tmp_path: Path,
) -> None:
    source = _native_backup(
        tmp_path / "backup.tar",
        sites=_sites_archive(include_version=False),
    )

    inspection = inspect_source(source, source_version="8.2.0")
    plan = create_plan(inspection)

    assert not plan.execution_allowed
    assert "must contain version.php" in " ".join(plan.blockers)


def test_archive_path_traversal_and_links_are_rejected(tmp_path: Path) -> None:
    traversal = io.BytesIO()
    with tarfile.open(fileobj=traversal, mode="w:gz") as archive:
        _add_bytes(archive, "../version.php", b"unsafe")
    with pytest.raises(ToolError, match="traversal"):
        inspect_source(
            _native_backup(
                tmp_path / "traversal.tar",
                sites=traversal.getvalue(),
            )
        )

    linked = io.BytesIO()
    with tarfile.open(fileobj=linked, mode="w:gz") as archive:
        member = tarfile.TarInfo("sites/default/documents/link")
        member.type = tarfile.SYMTYPE
        member.linkname = "/etc/passwd"
        archive.addfile(member)
    with pytest.raises(ToolError, match="links"):
        inspect_source(
            _native_backup(
                tmp_path / "link.tar",
                sites=linked.getvalue(),
            )
        )


def test_archive_limits_are_enforced_before_planning(tmp_path: Path) -> None:
    source = _native_backup(tmp_path / "backup.tar")

    with pytest.raises(ToolError, match="limits exceeded"):
        inspect_source(source, limits=ArchiveLimits(max_members=2))


def test_cli_inspect_and_plan_are_offline_and_do_not_leak_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _native_backup(
        tmp_path / "backup.tar",
        patient_marker=b"do-not-print-this-patient",
    )
    inspection_path = tmp_path / "inspection.json"
    plan_path = tmp_path / "plan.json"

    def deny_session(*args: object, **kwargs: object) -> None:
        raise AssertionError("offline commands must not create an AWS session")

    monkeypatch.setattr("boto3.Session", deny_session)

    assert main(["inspect", str(source), "--output", str(inspection_path)]) == 0
    assert (
        main(
            [
                "plan",
                str(inspection_path),
                "--output",
                str(plan_path),
            ]
        )
        == 0
    )
    output = inspection_path.read_text() + plan_path.read_text()
    assert "do-not-print-this-patient" not in output
    assert json.loads(plan_path.read_text())["execution_allowed"] is True


def test_execute_stays_locked_without_all_confirmations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _native_backup(tmp_path / "backup.tar")
    plan = create_plan(inspect_source(source))
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")

    def deny_session(*args: object, **kwargs: object) -> None:
        raise AssertionError("locked execution must not create an AWS session")

    monkeypatch.setattr("boto3.Session", deny_session)

    exit_code = main(
        [
            "execute",
            "--plan",
            str(plan_path),
            "--source",
            str(source),
            "--account-id",
            "123456789012",
            "--region",
            "us-east-1",
            "--stack-name",
            "OpenEMR",
            "--confirmation-token",
            "wrong",
        ]
    )

    assert exit_code == 2


def test_ambiguous_task_launch_preserves_stopped_service_and_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _native_backup(tmp_path / "backup.tar")
    plan = create_plan(inspect_source(source))
    plan_path = tmp_path / "plan.json"
    plan_path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
    state_path = tmp_path / "state" / "receipt.json"
    account_id = "111122223333"
    region = "us-east-1"
    stack_name = "OpenemrEcsStack"
    context = SimpleNamespace(
        account_id=account_id,
        openemr_version=plan.target_openemr_version,
        import_target_mode="fresh-target-only",
        region=region,
        stack_name=stack_name,
        cluster_name="openemr-cluster",
        service_name="openemr-service",
        service_url="https://openemr.example.test",
        task_definition_arn="arn:aws:ecs:us-east-1:111122223333:task-definition/import:1",
        staging_bucket="private-staging-bucket",
    )
    desired_counts: list[int] = []
    scaling_suspension: list[bool] = []
    cleanup_called = False

    monkeypatch.setattr(cli, "_boto3_session", lambda **kwargs: object())
    monkeypatch.setattr("tools.openemr_import.aws.resolve_stack_context", lambda **kwargs: context)
    monkeypatch.setattr("tools.openemr_import.aws.assert_service_stable", lambda *args, **kwargs: 1)
    monkeypatch.setattr("tools.openemr_import.aws.assert_service_autoscaling_active", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "tools.openemr_import.aws.recent_recovery_points",
        lambda *args, **kwargs: (
            SimpleNamespace(recovery_point_arn="arn:backup:rds", creation_date="2026-07-31T00:00:00+00:00"),
            SimpleNamespace(recovery_point_arn="arn:backup:efs", creation_date="2026-07-31T00:00:00+00:00"),
        ),
    )
    monkeypatch.setattr("tools.openemr_import.aws.acquire_import_lock", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        "tools.openemr_import.aws.upload_source",
        lambda *args, **kwargs: f"migrations/{plan.migration_id}/source.tar",
    )
    monkeypatch.setattr(
        "tools.openemr_import.aws.set_service_desired_count",
        lambda *args, desired_count, **kwargs: desired_counts.append(desired_count),
    )
    monkeypatch.setattr(
        "tools.openemr_import.aws.set_service_autoscaling_suspended",
        lambda *args, suspended, **kwargs: scaling_suspension.append(suspended),
    )

    def ambiguous_launch(*args: object, **kwargs: object) -> None:
        raise AwsImportError("malformed ECS launch response")

    def unexpected_cleanup(*args: object, **kwargs: object) -> None:
        nonlocal cleanup_called
        cleanup_called = True

    monkeypatch.setattr("tools.openemr_import.aws.start_import_task", ambiguous_launch)
    monkeypatch.setattr("tools.openemr_import.aws.cleanup_staging_scope", unexpected_cleanup)

    args = argparse.Namespace(
        plan=plan_path,
        source=source,
        account_id=account_id,
        region=region,
        stack_name=stack_name,
        maximum_recovery_age_hours=24,
        maximum_wait_attempts=1,
        allow_aws_execution=True,
        confirm_fresh_target=True,
        confirm_downtime=True,
        confirm_recovery_points=True,
        confirm_destructive_import=True,
        confirmation_token=f"IMPORT:{account_id}:{region}:{stack_name}:{plan.configuration_fingerprint}",
        state=state_path,
        profile=None,
    )

    with pytest.raises(ToolError, match="launch outcome is unknown"):
        cli._execute_command(args)

    assert desired_counts == [0]
    assert scaling_suspension == [True]
    assert cleanup_called is False
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["status"] == "launch-outcome-unknown"
    assert state["original_desired_count"] == 1
    assert state["service_remains_stopped"] is True
    assert state["autoscaling_remains_suspended"] is True


def test_plan_json_rejects_truthy_strings_for_safety_flags(tmp_path: Path) -> None:
    source = _native_backup(tmp_path / "backup.tar")
    data = create_plan(inspect_source(source)).to_dict()
    data["execution_allowed"] = "false"

    with pytest.raises(ToolError, match="malformed"):
        plan_from_dict(data)
