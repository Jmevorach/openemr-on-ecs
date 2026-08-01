"""Unit tests for the isolated import worker's filesystem boundaries."""

from __future__ import annotations

import base64
import gzip
import importlib.util
import io
import os
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_VALID_SEVEN_KEY = b"007" + base64.b64encode(b"k" * 112)


def _worker() -> ModuleType:
    path = Path(__file__).resolve().parents[2] / "tools" / "openemr-import-worker" / "worker.py"
    spec = importlib.util.spec_from_file_location("openemr_import_worker", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _add(
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


def _sites(
    path: Path,
    *,
    unsafe_upload: bool = False,
    invalid_keys: bool = False,
) -> Path:
    key_material = b"not-an-openemr-key" if invalid_keys else _VALID_SEVEN_KEY
    with tarfile.open(path, mode="w:gz") as archive:
        _add(
            archive,
            "version.php",
            b"<?php $v_major='8'; $v_minor='2'; $v_patch='0'; " b"$v_tag=''; $v_realpatch='0';",
        )
        _add(archive, "sites/default/sqlconf.php", b"source-credential")
        _add(archive, "sites/default/config.php", b"source-config")
        _add(archive, "sites/default/documents/patient.pdf", b"patient")
        _add(
            archive,
            "sites/default/documents/logs_and_misc/methods/sevena",
            key_material,
        )
        _add(
            archive,
            "sites/default/documents/logs_and_misc/methods/sevenb",
            key_material,
        )
        _add(archive, "sites/default/images/logo.png", b"logo")
        _add(archive, "sites/default/referral_template.html", b"template")
        if unsafe_upload:
            _add(
                archive,
                "sites/default/documents/payload.php",
                b"<?php echo 1;",
            )
    return path


def test_worker_extracts_only_data_allowlist_and_never_source_credentials(
    tmp_path: Path,
) -> None:
    worker = _worker()
    destination = tmp_path / "import" / "default"
    destination.mkdir(parents=True)

    version = worker._validate_and_extract_sites(
        _sites(tmp_path / "sites.tar.gz"),
        destination,
    )

    assert version == "8.2.0"
    assert (destination / "documents" / "patient.pdf").read_bytes() == b"patient"
    assert (destination / "images" / "logo.png").read_bytes() == b"logo"
    assert (destination / "referral_template.html").read_bytes() == b"template"
    assert not (destination / "sqlconf.php").exists()
    assert not (destination / "config.php").exists()
    assert b"source-credential" not in b"".join(path.read_bytes() for path in destination.rglob("*") if path.is_file())


def test_worker_rejects_script_like_content_in_imported_data(tmp_path: Path) -> None:
    worker = _worker()
    destination = tmp_path / "import" / "default"
    destination.mkdir(parents=True)

    with pytest.raises(worker.ImportFailure, match="custom-executable-content"):
        worker._validate_and_extract_sites(
            _sites(tmp_path / "sites.tar.gz", unsafe_upload=True),
            destination,
        )


def test_worker_rejects_malformed_current_encryption_keys(tmp_path: Path) -> None:
    worker = _worker()
    destination = tmp_path / "import" / "default"
    destination.mkdir(parents=True)

    with pytest.raises(worker.ImportFailure, match="invalid-document-encryption-keys"):
        worker._validate_and_extract_sites(
            _sites(tmp_path / "sites.tar.gz", invalid_keys=True),
            destination,
        )


def test_site_swap_preserves_target_configuration_and_rollback_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    mount_root = tmp_path / "mount"
    target = mount_root / "default"
    (target / "documents" / "certificates").mkdir(parents=True)
    (target / "config.php").write_bytes(b"target-config")
    (target / "sqlconf.php").write_bytes(b"target-credential")
    (target / "documents" / "certificates" / "mysql-ca").write_bytes(b"target-ca")
    (target / "documents" / "fresh-placeholder").write_bytes(b"old")

    imported = tmp_path / "imported"
    (imported / "documents" / "logs_and_misc" / "methods").mkdir(parents=True)
    (imported / "documents" / "patient.pdf").write_bytes(b"patient")
    (imported / "documents" / "logs_and_misc" / "methods" / "sevena").write_bytes(_VALID_SEVEN_KEY)
    (imported / "documents" / "logs_and_misc" / "methods" / "sevenb").write_bytes(_VALID_SEVEN_KEY)

    worker._stage_and_swap_sites(imported, mount_root, "import-0123456789abcdef")

    assert (target / "config.php").read_bytes() == b"target-config"
    assert (target / "sqlconf.php").read_bytes() == b"target-credential"
    assert (target / "documents" / "patient.pdf").read_bytes() == b"patient"
    assert (target / "documents" / "certificates" / "mysql-ca").read_bytes() == b"target-ca"
    assert not (target / "documents" / "fresh-placeholder").exists()
    backup = mount_root / ".openemr-import-backup" / "import-0123456789abcdef" / "default"
    assert (backup / "documents" / "fresh-placeholder").read_bytes() == b"old"

    monkeypatch.setenv("OPENEMR_SITES_MOUNT_ROOT", str(mount_root))
    worker._cleanup_site_artifacts(
        "import-0123456789abcdef",
        delete_backup=True,
    )
    assert not backup.exists()


def test_sql_validation_is_bounded_and_recognizes_native_dump(tmp_path: Path) -> None:
    worker = _worker()
    source = tmp_path / "openemr.sql.gz"
    source.write_bytes(
        gzip.compress(
            b"-- MySQL dump\nCREATE TABLE `patient_data` (`id` int);\n" b"INSERT INTO `patient_data` VALUES (1);\n"
        )
    )
    output = tmp_path / "validated.sql"

    worker._validate_sql(source, output)

    assert output.read_bytes().startswith(b"-- MySQL dump")


def test_sql_validation_rejects_client_commands_anywhere_in_dump(tmp_path: Path) -> None:
    worker = _worker()
    source = tmp_path / "openemr.sql"
    source.write_bytes(
        b"-- MySQL dump\nCREATE TABLE `patient_data` (`id` int);\n"
        + (b"-- padding\n" * (worker.CHUNK_SIZE // 5))
        + b"\\! touch /tmp/escaped\n"
    )

    with pytest.raises(worker.ImportFailure, match="unsafe-sql-client-command"):
        worker._validate_sql(source, tmp_path / "validated.sql")


def test_site_validation_requires_canonical_nonempty_encryption_keys(tmp_path: Path) -> None:
    worker = _worker()
    source = tmp_path / "sites.tar.gz"
    with tarfile.open(source, mode="w:gz") as archive:
        _add(
            archive,
            "version.php",
            b"<?php $v_major='8'; $v_minor='2'; $v_patch='0'; $v_tag='';",
        )
        _add(archive, "sites/default/sqlconf.php", b"source-credential")
        _add(archive, "sites/default/documents/patient.pdf", b"patient")
        _add(archive, "sites/default/documents/decoy/sevena", b"a")
        _add(archive, "sites/default/documents/decoy/sevenb", b"b")

    destination = tmp_path / "import" / "default"
    destination.mkdir(parents=True)
    with pytest.raises(worker.ImportFailure, match="missing-document-encryption-keys"):
        worker._validate_and_extract_sites(source, destination)


def test_efs_mutability_probe_is_removed_after_atomic_rename(tmp_path: Path) -> None:
    worker = _worker()
    mount_root = tmp_path / "mount"
    (mount_root / "default").mkdir(parents=True)

    worker._assert_efs_mutable(mount_root, "import-0123456789abcdef")

    assert not list(mount_root.glob(".openemr-import-probe-*"))


def test_fresh_efs_check_rejects_existing_documents_but_allows_baseline_files(
    tmp_path: Path,
) -> None:
    worker = _worker()
    mount_root = tmp_path / "mount"
    methods = mount_root / "default" / "documents" / "logs_and_misc" / "methods"
    methods.mkdir(parents=True)
    (methods / "sevena").write_bytes(_VALID_SEVEN_KEY)
    certificates = mount_root / "default" / "documents" / "certificates"
    certificates.mkdir()
    (certificates / "mysql-ca").write_text("ca", encoding="utf-8")

    worker._assert_fresh_efs_target(mount_root)

    (mount_root / "default" / "documents" / "patient.pdf").write_bytes(b"patient")
    with pytest.raises(worker.ImportFailure, match="target-site-is-not-empty"):
        worker._assert_fresh_efs_target(mount_root)


def test_automatic_rollback_restores_site_and_database_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    migration_id = "import-0123456789abcdef"
    mount_root = tmp_path / "mount"
    target = mount_root / "default"
    target.mkdir(parents=True)
    (target / "state").write_text("imported", encoding="utf-8")
    backup = mount_root / ".openemr-import-backup" / migration_id / "default"
    backup.mkdir(parents=True)
    (backup / "state").write_text("original", encoding="utf-8")
    baseline = backup.parent / "target-baseline.sql"
    baseline.write_text("-- baseline", encoding="utf-8")
    restored: list[Path] = []
    monkeypatch.setattr(
        worker,
        "_restore_baseline_database",
        lambda path: restored.append(path),
    )

    assert worker._attempt_automatic_rollback(
        mount_root=mount_root,
        migration_id=migration_id,
        baseline_sql=baseline,
        database_mutation_started=True,
    )
    assert (target / "state").read_text(encoding="utf-8") == "original"
    assert restored == [baseline]


def test_database_command_never_contains_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    monkeypatch.setenv("MYSQL_HOST", "db.internal")
    monkeypatch.setenv("MYSQL_PORT", "3306")
    monkeypatch.setenv("MYSQL_USERNAME", "admin")
    monkeypatch.setenv("MYSQL_PASSWORD", "must-not-appear")
    monkeypatch.setenv("MYSQL_SSL_CA", "/ca.pem")

    command = worker._mysql_command("openemr")

    assert "must-not-appear" not in " ".join(command)
    assert "--binary-mode" in command
    assert "--local-infile=0" in command
    assert "--sandbox" in command
    assert "--ssl-verify-server-cert" in command
    assert os.environ["MYSQL_PASSWORD"] == "must-not-appear"


def test_status_object_binds_bucket_owner_and_customer_managed_kms_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    key_arn = "arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000000"
    monkeypatch.setenv("IMPORT_STAGING_BUCKET_OWNER", "123456789012")
    monkeypatch.setenv("IMPORT_STAGING_KMS_KEY_ARN", key_arn)

    class S3:
        arguments: dict[str, Any] | None = None

        def put_object(self, **kwargs: Any) -> None:
            self.arguments = kwargs

    s3 = S3()
    worker._put_status(
        s3,
        bucket="staging",
        migration_id="import-0123456789abcdef",
        status="running",
        phase="download",
    )

    assert s3.arguments is not None
    assert s3.arguments["ExpectedBucketOwner"] == "123456789012"
    assert s3.arguments["ServerSideEncryption"] == "aws:kms"
    assert s3.arguments["SSEKMSKeyId"] == key_arn


def test_database_dump_runs_as_temporary_database_scoped_user(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    sql = tmp_path / "validated.sql"
    sql.write_bytes(b"CREATE TABLE patient_data (id int);\n")
    calls: list[dict[str, object]] = []

    def fake_run_mysql(
        *extra: str,
        stdin: Any = None,
        username: str | None = None,
        password: str | None = None,
    ) -> str:
        body = stdin.read() if hasattr(stdin, "read") else b""
        calls.append(
            {
                "extra": extra,
                "body": body,
                "username": username,
                "password": password,
            }
        )
        return ""

    monkeypatch.setattr(worker, "_run_mysql", fake_run_mysql)
    monkeypatch.setenv("MYSQL_DATABASE", "openemr")

    worker._replace_database(sql, "import-0123456789abcdef")

    assert len(calls) == 4
    setup = calls[1]
    setup_body = setup["body"]
    assert isinstance(setup_body, bytes)
    assert b"GRANT ALL PRIVILEGES ON `openemr`.*" in setup_body
    assert b"REQUIRE SSL" in setup_body
    import_call = calls[2]
    assert import_call["extra"] == ("openemr",)
    assert import_call["username"] == "oe_import_0123456789abcdef"
    assert import_call["password"]
    assert import_call["body"] == sql.read_bytes()
    assert calls[3]["body"] == b"DROP USER IF EXISTS 'oe_import_0123456789abcdef'@'%';\n"


def test_temporary_database_user_cleanup_runs_when_setup_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _worker()
    sql = tmp_path / "validated.sql"
    sql.write_bytes(b"CREATE TABLE patient_data (id int);\n")
    calls: list[bytes] = []

    def fake_run_mysql(
        *extra: str,
        stdin: Any = None,
        username: str | None = None,
        password: str | None = None,
    ) -> str:
        del extra, username, password
        body = stdin.read() if hasattr(stdin, "read") else b""
        calls.append(body)
        if len(calls) == 2:
            raise worker.ImportFailure("database-command-failed")
        return ""

    monkeypatch.setattr(worker, "_run_mysql", fake_run_mysql)
    monkeypatch.setenv("MYSQL_DATABASE", "openemr")

    with pytest.raises(worker.ImportFailure, match="database-command-failed"):
        worker._replace_database(sql, "import-0123456789abcdef")

    assert len(calls) == 3
    assert calls[-1] == b"DROP USER IF EXISTS 'oe_import_0123456789abcdef'@'%';\n"
