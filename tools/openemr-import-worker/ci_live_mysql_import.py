"""CI harness: exercise worker DB/site import phases against live TLS MySQL.

This intentionally bypasses S3 download/status publishing from main(). It calls
the same post-download worker helpers used in production import.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import worker as import_worker


class HarnessFailure(RuntimeError):
    """Harness-level failure with a redacted reason."""


def _emit(payload: dict[str, object]) -> None:
    print(json.dumps(payload, sort_keys=True), flush=True)


def _require_env(*names: str) -> None:
    missing = [name for name in names if not os.environ.get(name)]
    if missing:
        raise HarnessFailure(f"missing-env:{','.join(missing)}")


def _migration_id() -> str:
    value = os.environ.get("IMPORT_MIGRATION_ID", "import-0123456789abcdef")
    if not re.fullmatch(r"import-[a-f0-9]{16}", value):
        raise HarnessFailure("invalid-migration-id")
    return value


def _mount_root() -> Path:
    return Path(os.environ.get("OPENEMR_SITES_MOUNT_ROOT", "/mnt/openemr-sites")).resolve()


def _source_tar() -> Path:
    path = Path(os.environ["IMPORT_SOURCE_TAR"]).resolve()
    if not path.is_file():
        raise HarnessFailure("missing-source-tar")
    return path


def _patient_count() -> int:
    database = os.environ.get("MYSQL_DATABASE", "openemr")
    value = import_worker._run_mysql(database, "--execute=SELECT COUNT(*) FROM `patient_data`")
    try:
        return int(value.splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise HarnessFailure("patient-count-unreadable") from exc


def _table_count() -> int:
    database = os.environ.get("MYSQL_DATABASE", "openemr")
    tables = import_worker._run_mysql(database, "--execute=SHOW TABLES")
    return len([line for line in tables.splitlines() if line.strip()])


def _expected_identity() -> tuple[str, int]:
    target_version = os.environ.get("TARGET_OPENEMR_VERSION", "")
    try:
        target_database_version = int(os.environ["TARGET_DATABASE_VERSION"])
    except (KeyError, ValueError) as exc:
        raise HarnessFailure("invalid-target-database-version") from exc
    return target_version, target_database_version


def _reset_target_from_fixtures(*, mount_root: Path, fixtures: Path) -> None:
    """Restore empty DB + fresh sites between happy and rollback scenarios."""

    baseline = fixtures / "empty-baseline.sql"
    template = fixtures / "fresh-sites"
    if not baseline.is_file() or not (template / "default").is_dir():
        raise HarnessFailure("missing-reset-fixtures")
    import_worker._restore_baseline_database(baseline)
    if mount_root.exists():
        for child in mount_root.iterdir():
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    else:
        mount_root.mkdir(parents=True, mode=0o755)
    shutil.copytree(template / "default", mount_root / "default")


def _prepare_validated_source(
    work: Path,
    source: Path,
) -> tuple[Path, Path, str, int]:
    sql_artifact, sites_artifact, _hashes = import_worker._unpack_native_source(source, work)
    work_default = work / "sites" / "default"
    work_default.mkdir(parents=True, mode=0o700)
    source_version, source_database_version = import_worker._validate_and_extract_sites(
        sites_artifact,
        work_default,
    )
    sites_artifact.unlink(missing_ok=True)
    target_version, target_database_version = _expected_identity()
    if import_worker.Version(source_version) != import_worker.Version(target_version):
        raise import_worker.ImportFailure("source-target-version-mismatch")
    if source_database_version != target_database_version:
        raise import_worker.ImportFailure("source-target-database-version-mismatch")
    validated_sql = work / "validated.sql"
    sql_version, sql_database_version = import_worker._validate_sql(
        sql_artifact,
        validated_sql,
    )
    sql_artifact.unlink(missing_ok=True)
    if (sql_version, sql_database_version) != (
        source_version,
        source_database_version,
    ):
        raise import_worker.ImportFailure("source-version-artifacts-mismatch")
    return (
        validated_sql,
        work_default,
        source_version,
        source_database_version,
    )


def _run_happy(*, migration_id: str, mount_root: Path, source: Path) -> None:
    work = Path("/work") / f"{migration_id}-happy"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, mode=0o700)
    sqlconf_before = (mount_root / "default" / "sqlconf.php").read_bytes()
    marker = b"ci-import-marker-document"
    try:
        expected_version, expected_database_version = _expected_identity()
        import_worker._phase("target-validation")
        import_worker._assert_efs_mutable(mount_root, migration_id)
        import_worker._assert_fresh_efs_target(mount_root)
        import_worker._assert_empty_target(
            expected_version,
            expected_database_version,
        )

        import_worker._phase("source-validation")
        (
            validated_sql,
            work_default,
            source_version,
            source_database_version,
        ) = _prepare_validated_source(work, source)

        import_worker._phase("recovery-baseline")
        rollback_root = mount_root / ".openemr-import-backup" / migration_id
        shutil.rmtree(rollback_root, ignore_errors=True)
        rollback_root.mkdir(parents=True, mode=0o700)
        baseline_sql = rollback_root / "target-baseline.sql"
        import_worker._dump_target_database(baseline_sql)

        import_worker._phase("database-import")
        import_worker._replace_database(validated_sql, migration_id)

        import_worker._phase("site-import")
        import_worker._stage_and_swap_sites(work_default, mount_root, migration_id)

        import_worker._phase("post-import-validation")
        import_worker._validate_import(
            mount_root,
            source_version,
            source_database_version,
        )

        if _patient_count() < 1:
            raise HarnessFailure("happy-path-missing-patient")
        if _table_count() < 50:
            raise HarnessFailure("happy-path-insufficient-tables")
        document = mount_root / "default" / "documents" / "ci-import-marker.txt"
        if not document.is_file() or document.read_bytes() != marker:
            raise HarnessFailure("happy-path-missing-marker-document")
        if (mount_root / "default" / "sqlconf.php").read_bytes() != sqlconf_before:
            raise HarnessFailure("happy-path-sqlconf-changed")
        if b"source-credential" in (mount_root / "default" / "sqlconf.php").read_bytes():
            raise HarnessFailure("happy-path-source-sqlconf-leaked")
        _emit({"scenario": "happy", "status": "passed", "tables": _table_count(), "patients": _patient_count()})
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _run_rollback(*, migration_id: str, mount_root: Path, source: Path) -> None:
    work = Path("/work") / f"{migration_id}-rollback"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, mode=0o700)
    sqlconf_before = (mount_root / "default" / "sqlconf.php").read_bytes()
    baseline_sql: Path | None = None
    try:
        expected_version, expected_database_version = _expected_identity()
        import_worker._phase("target-validation")
        import_worker._assert_efs_mutable(mount_root, f"{migration_id}r")
        import_worker._assert_fresh_efs_target(mount_root)
        import_worker._assert_empty_target(
            expected_version,
            expected_database_version,
        )
        if _patient_count() != 0:
            raise HarnessFailure("rollback-precondition-not-empty")

        import_worker._phase("source-validation")
        validated_sql, _work_default, _source_version, _source_database_version = _prepare_validated_source(
            work, source
        )

        import_worker._phase("recovery-baseline")
        rollback_root = mount_root / ".openemr-import-backup" / migration_id
        shutil.rmtree(rollback_root, ignore_errors=True)
        rollback_root.mkdir(parents=True, mode=0o700)
        baseline_sql = rollback_root / "target-baseline.sql"
        import_worker._dump_target_database(baseline_sql)

        import_worker._phase("database-import")
        import_worker._replace_database(validated_sql, migration_id)
        if _patient_count() < 1:
            raise HarnessFailure("rollback-replace-did-not-load-source")

        import_worker._phase("site-import")
        raise import_worker.ImportFailure("simulated-site-import-failure")
    except import_worker.ImportFailure as exc:
        if str(exc) != "simulated-site-import-failure":
            raise
        import_worker._phase("automatic-rollback")
        ok = import_worker._attempt_automatic_rollback(
            mount_root=mount_root,
            migration_id=migration_id,
            baseline_sql=baseline_sql,
            database_mutation_started=True,
        )
        if not ok:
            raise HarnessFailure("automatic-rollback-failed") from exc
        if _patient_count() != 0:
            raise HarnessFailure("rollback-left-source-patients")
        if (mount_root / "default" / "sqlconf.php").read_bytes() != sqlconf_before:
            raise HarnessFailure("rollback-sqlconf-changed")
        if (mount_root / "default" / "documents" / "ci-import-marker.txt").exists():
            raise HarnessFailure("rollback-imported-marker-present")
        _emit({"scenario": "rollback", "status": "passed", "patients": _patient_count()})
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _run_recovery(*, migration_id: str, mount_root: Path, source: Path) -> None:
    """Simulate hard termination after both database and EFS mutation."""

    work = Path("/work") / f"{migration_id}-recovery"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, mode=0o700)
    sqlconf_before = (mount_root / "default" / "sqlconf.php").read_bytes()
    try:
        _emit({"phase": "target-validation", "scenario": "recovery"})
        expected_version, expected_database_version = _expected_identity()
        import_worker._assert_fresh_efs_target(mount_root)
        import_worker._assert_empty_target(
            expected_version,
            expected_database_version,
        )
        _emit({"phase": "source-validation", "scenario": "recovery"})
        (
            validated_sql,
            work_default,
            _source_version,
            _source_database_version,
        ) = _prepare_validated_source(work, source)
        _emit({"phase": "recovery-baseline", "scenario": "recovery"})
        rollback_root = mount_root / ".openemr-import-backup" / migration_id
        shutil.rmtree(rollback_root, ignore_errors=True)
        rollback_root.mkdir(parents=True, mode=0o700)
        import_worker._dump_target_database(rollback_root / "target-baseline.sql")
        _emit({"phase": "database-import", "scenario": "recovery"})
        import_worker._replace_database(validated_sql, migration_id)
        _emit({"phase": "site-import", "scenario": "recovery"})
        import_worker._stage_and_swap_sites(
            work_default,
            mount_root,
            migration_id,
        )
        if _patient_count() < 1:
            raise HarnessFailure("recovery-replace-did-not-load-source")

        _emit({"phase": "fresh-process-recovery", "scenario": "recovery"})
        recovered = subprocess.run(
            [
                sys.executable,
                str(Path(import_worker.__file__).resolve()),
                "--operation",
                "recover",
                "--migration-id",
                migration_id,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=7200,
        )
        if recovered.returncode != 0:
            raise HarnessFailure("fresh-process-recovery-failed")

        if _patient_count() != 0:
            raise HarnessFailure("recovery-left-source-patients")
        if (mount_root / "default" / "sqlconf.php").read_bytes() != sqlconf_before:
            raise HarnessFailure("recovery-sqlconf-changed")
        if (mount_root / "default" / "documents" / "ci-import-marker.txt").exists():
            raise HarnessFailure("recovery-imported-marker-present")
        _emit(
            {
                "scenario": "recovery",
                "status": "passed",
                "patients": _patient_count(),
            }
        )
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="CI live MySQL import-worker harness")
    parser.add_argument(
        "--scenario",
        choices=("happy", "rollback", "recovery", "all"),
        default=os.environ.get("IMPORT_SCENARIO", "all"),
    )
    args = parser.parse_args(argv)

    try:
        _require_env(
            "MYSQL_HOST",
            "MYSQL_PORT",
            "MYSQL_USERNAME",
            "MYSQL_PASSWORD",
            "MYSQL_SSL_CA",
            "TARGET_OPENEMR_VERSION",
            "IMPORT_SOURCE_TAR",
        )
        migration_id = _migration_id()
        mount_root = _mount_root()
        source = _source_tar()
        fixtures = Path(os.environ.get("IMPORT_FIXTURES_DIR", "/fixtures")).resolve()

        if args.scenario in {"happy", "all"}:
            _run_happy(migration_id=migration_id, mount_root=mount_root, source=source)
        if args.scenario in {"rollback", "all"}:
            if args.scenario == "all":
                _reset_target_from_fixtures(mount_root=mount_root, fixtures=fixtures)
                # Distinct migration id so leftover happy-path backup dirs do not collide.
                os.environ["IMPORT_MIGRATION_ID"] = "import-fedcba9876543210"
                migration_id = _migration_id()
            _run_rollback(migration_id=migration_id, mount_root=mount_root, source=source)
        if args.scenario in {"recovery", "all"}:
            if args.scenario == "all":
                _reset_target_from_fixtures(
                    mount_root=mount_root,
                    fixtures=fixtures,
                )
                os.environ["IMPORT_MIGRATION_ID"] = "import-0011223344556677"
                migration_id = _migration_id()
            _run_recovery(
                migration_id=migration_id,
                mount_root=mount_root,
                source=source,
            )
        _emit({"status": "passed", "scenario": args.scenario})
        return 0
    except (HarnessFailure, import_worker.ImportFailure) as exc:
        _emit({"status": "failed", "error": str(exc)})
        return 1
    except Exception as exc:  # pragma: no cover - unexpected harness crash
        _emit({"status": "failed", "error": f"internal-harness-error:{type(exc).__name__}"})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
