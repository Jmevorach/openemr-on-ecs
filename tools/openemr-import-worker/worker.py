"""Isolated fresh-target OpenEMR import worker.

The worker is intentionally standalone so its Docker build context stays small.
It never logs archive member names, SQL content, credentials, or patient data.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
from pathlib import Path, PurePosixPath
from typing import IO, Any

import boto3
from packaging.version import InvalidVersion, Version

MAX_MEMBERS = 100_000
MAX_MEMBER_BYTES = 2 * 1024**3
MAX_EXPANDED_BYTES = 20 * 1024**3
MAX_NESTED_ARCHIVE_BYTES = 4 * 1024**3
MAX_COMPRESSION_RATIO = 200
CHUNK_SIZE = 1024 * 1024
EXECUTABLE_SUFFIXES = (".cgi", ".js", ".php", ".pl", ".py", ".sh")
IMPORTED_DIRECTORY_ROOTS = {"LBF", "documents", "images"}
IMPORTED_TOP_LEVEL_FILES = {
    "clickoptions.txt",
    "faxcover.txt",
    "faxtitle.eps",
    "referral_template.html",
}
TARGET_ONLY_FILENAMES = {
    ".htaccess",
    ".user.ini",
    "web.config",
}
VERSION_FIELD = re.compile(rb"\$(v_major|v_minor|v_patch|v_tag|v_realpatch)\s*=\s*['\"]([^'\"]*)['\"]")
SQL_CLIENT_COMMANDS = (
    b"\\!",
    b"\\.",
    b"\\e",
    b"\\p",
    b"\\r",
    b"\\t",
    b"edit",
    b"pager",
    b"prompt",
    b"source",
    b"system",
    b"tee",
)
SQL_CLIENT_COMMAND_PATTERN = re.compile(
    rb"(?:^|\n)[ \t]*(?:\\[!.ePrRtT]|(?:edit|pager|prompt|source|system|tee)(?=[ \t\r\n;]))",
    re.IGNORECASE,
)


class ImportFailure(RuntimeError):
    """A redacted worker failure safe to publish as status."""


def _phase(name: str) -> None:
    print(json.dumps({"phase": name}, sort_keys=True), flush=True)


def _safe_path(raw_name: str) -> PurePosixPath:
    if "\x00" in raw_name or "\\" in raw_name:
        raise ImportFailure("unsafe-archive-path")
    name = raw_name
    while name.startswith("./"):
        name = name[2:]
    if not name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ImportFailure("unsafe-archive-path")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ImportFailure("unsafe-archive-path")
    return path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_fingerprint(values: dict[str, str]) -> str:
    payload = json.dumps(
        values,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _copy_limited(source: IO[bytes], destination: IO[bytes], limit: int) -> int:
    total = 0
    while True:
        chunk = source.read(CHUNK_SIZE)
        if not chunk:
            return total
        total += len(chunk)
        if total > limit:
            raise ImportFailure("artifact-size-limit")
        destination.write(chunk)


def _unpack_native_source(source: Path, work: Path) -> tuple[Path, Path, dict[str, str]]:
    sites_path = work / "openemr.tar.gz"
    found: dict[str, tuple[Path, str]] = {}
    seen: set[str] = set()
    folded: set[str] = set()
    total = 0
    members = 0
    try:
        archive = tarfile.open(source, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ImportFailure("malformed-native-backup") from exc
    with archive:
        for member in archive:
            if member.isdir() and member.name in {".", "./"}:
                continue
            path = _safe_path(member.name)
            normalized = path.as_posix()
            if normalized in seen or normalized.casefold() in folded:
                raise ImportFailure("duplicate-archive-member")
            seen.add(normalized)
            folded.add(normalized.casefold())
            members += 1
            total += member.size
            if members > MAX_MEMBERS or total > MAX_EXPANDED_BYTES:
                raise ImportFailure("native-backup-limit")
            if not member.isfile():
                if member.isdir():
                    continue
                raise ImportFailure("special-archive-member")
            if len(path.parts) != 1:
                continue
            if path.name in {"openemr.sql", "openemr.sql.gz"}:
                kind = "sql"
                destination = work / path.name
            elif path.name == "openemr.tar.gz":
                kind = "sites"
                destination = sites_path
            else:
                continue
            if kind in found:
                raise ImportFailure("duplicate-required-artifact")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ImportFailure("unreadable-required-artifact")
            digest = hashlib.sha256()
            with destination.open("xb") as output:
                copied = 0
                while True:
                    chunk = extracted.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > MAX_NESTED_ARCHIVE_BYTES:
                        raise ImportFailure("artifact-size-limit")
                    digest.update(chunk)
                    output.write(chunk)
            found[kind] = (destination, digest.hexdigest())
    if set(found) != {"sql", "sites"}:
        raise ImportFailure("missing-required-artifact")
    return (
        found["sql"][0],
        found["sites"][0],
        {"sql": found["sql"][1], "sites": found["sites"][1]},
    )


def _parse_version(content: bytes) -> str:
    fields = {
        key.decode("ascii"): value.decode("utf-8", errors="strict").strip()
        for key, value in VERSION_FIELD.findall(content)
    }
    if not all(field in fields for field in ("v_major", "v_minor", "v_patch")):
        raise ImportFailure("missing-source-version")
    value = f"{fields['v_major']}.{fields['v_minor']}.{fields['v_patch']}"
    realpatch = fields.get("v_realpatch", "")
    if realpatch and realpatch != "0":
        value = f"{value}.{realpatch}"
    tag = fields.get("v_tag", "")
    if tag:
        value = f"{value}{tag}"
    try:
        parsed = Version(value)
    except InvalidVersion as exc:
        raise ImportFailure("invalid-source-version") from exc
    if parsed.is_prerelease or parsed.is_devrelease:
        raise ImportFailure("prerelease-source")
    return str(parsed)


def _validate_and_extract_sites(
    archive_path: Path,
    destination: Path,
) -> str:
    seen: set[str] = set()
    folded: set[str] = set()
    members = 0
    expanded = 0
    version: str | None = None
    has_sqlconf = False
    has_documents = False
    has_sixa = False
    has_sixb = False
    try:
        archive = tarfile.open(archive_path, mode="r:*")
    except (tarfile.TarError, OSError) as exc:
        raise ImportFailure("malformed-sites-archive") from exc
    with archive:
        for member in archive:
            if member.isdir() and member.name in {".", "./"}:
                continue
            path = _safe_path(member.name)
            normalized = path.as_posix()
            if normalized in seen or normalized.casefold() in folded:
                raise ImportFailure("duplicate-archive-member")
            seen.add(normalized)
            folded.add(normalized.casefold())
            members += 1
            expanded += member.size
            if members > MAX_MEMBERS or member.size > MAX_MEMBER_BYTES or expanded > MAX_EXPANDED_BYTES:
                raise ImportFailure("sites-archive-limit")
            if not (member.isfile() or member.isdir()):
                raise ImportFailure("special-archive-member")
            if normalized == "version.php" and member.isfile():
                if member.size > 64 * 1024:
                    raise ImportFailure("invalid-source-version")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ImportFailure("invalid-source-version")
                version = _parse_version(extracted.read(64 * 1024 + 1))
            if len(path.parts) < 2 or path.parts[:2] != ("sites", "default"):
                continue
            relative = path.parts[2:]
            if not relative:
                continue
            if relative == ("sqlconf.php",):
                has_sqlconf = True
                continue
            if not (
                relative[0] in IMPORTED_DIRECTORY_ROOTS
                or (len(relative) == 1 and relative[0] in IMPORTED_TOP_LEVEL_FILES)
            ):
                continue
            if path.name.lower() in TARGET_ONLY_FILENAMES:
                continue
            if relative[0] == "documents":
                has_documents = True
                lowered_relative = tuple(part.lower() for part in relative)
                if lowered_relative == ("documents", "logs_and_misc", "methods", "sixa") and member.size > 0:
                    has_sixa = True
                if lowered_relative == ("documents", "logs_and_misc", "methods", "sixb") and member.size > 0:
                    has_sixb = True
            if member.isfile() and (bool(member.mode & 0o111) or path.name.lower().endswith(EXECUTABLE_SUFFIXES)):
                raise ImportFailure("custom-executable-content")
            output = destination.joinpath(*relative)
            resolved = output.resolve()
            try:
                resolved.relative_to(destination.resolve())
            except ValueError as exc:
                raise ImportFailure("unsafe-archive-path") from exc
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True, mode=0o700)
                output.chmod(0o700)
                continue
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ImportFailure("unreadable-sites-member")
            with output.open("xb") as target:
                copied = _copy_limited(extracted, target, member.size)
            if copied != member.size:
                raise ImportFailure("sites-member-size-mismatch")
            output.chmod(0o600)
    compressed = archive_path.stat().st_size
    if compressed and expanded > compressed * MAX_COMPRESSION_RATIO:
        raise ImportFailure("sites-compression-ratio")
    if not version:
        raise ImportFailure("missing-source-version")
    if not has_sqlconf or not has_documents:
        raise ImportFailure("incomplete-default-site")
    if not has_sixa or not has_sixb:
        raise ImportFailure("missing-document-encryption-keys")
    return version


def _validate_sql(sql_artifact: Path, output: Path) -> None:
    compressed = sql_artifact.name.endswith(".gz")
    prefix = bytearray()
    command_carry = b""
    total = 0
    try:
        source = gzip.open(sql_artifact, "rb") if compressed else sql_artifact.open("rb")
        with source, output.open("xb") as destination:
            while True:
                chunk = source.read(CHUNK_SIZE)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_EXPANDED_BYTES:
                    raise ImportFailure("sql-size-limit")
                if len(prefix) < 2 * CHUNK_SIZE:
                    prefix.extend(chunk[: 2 * CHUNK_SIZE - len(prefix)])
                command_scan = command_carry + chunk
                if SQL_CLIENT_COMMAND_PATTERN.search(command_scan):
                    raise ImportFailure("unsafe-sql-client-command")
                trailing = command_scan.rsplit(b"\n", 1)[-1].lstrip(b" \t\r").lower()
                if not trailing:
                    command_carry = b"\n"
                elif any(command.startswith(trailing) for command in SQL_CLIENT_COMMANDS):
                    command_carry = b"\n" + trailing
                else:
                    command_carry = b""
                destination.write(chunk)
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise ImportFailure("malformed-sql-artifact") from exc
    if compressed and sql_artifact.stat().st_size and total > (sql_artifact.stat().st_size * MAX_COMPRESSION_RATIO):
        raise ImportFailure("sql-compression-ratio")
    if command_carry.lstrip(b"\n") in SQL_CLIENT_COMMANDS:
        raise ImportFailure("unsafe-sql-client-command")
    sample = bytes(prefix).lower()
    if (
        b"\x00" in sample
        or not (b"mysql dump" in sample or b"mariadb dump" in sample)
        or not (b"create table" in sample or b"insert into" in sample or b"lock tables" in sample)
    ):
        raise ImportFailure("unrecognized-sql-dump")


def _mysql_command(*extra: str, username: str | None = None) -> list[str]:
    required = (
        "MYSQL_HOST",
        "MYSQL_PORT",
        "MYSQL_USERNAME",
        "MYSQL_PASSWORD",
        "MYSQL_SSL_CA",
    )
    if any(not os.environ.get(name) for name in required):
        raise ImportFailure("missing-database-configuration")
    return [
        "mariadb",
        "--batch",
        "--binary-mode",
        "--local-infile=0",
        "--sandbox",
        "--skip-column-names",
        "--connect-timeout=15",
        f"--host={os.environ['MYSQL_HOST']}",
        f"--port={os.environ['MYSQL_PORT']}",
        f"--user={username or os.environ['MYSQL_USERNAME']}",
        f"--ssl-ca={os.environ['MYSQL_SSL_CA']}",
        "--ssl-verify-server-cert",
        *extra,
    ]


def _run_mysql(
    *extra: str,
    stdin: IO[bytes] | None = None,
    username: str | None = None,
    password: str | None = None,
) -> str:
    env = {
        "HOME": os.environ.get("HOME", "/home/importer"),
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "MYSQL_PWD": password or os.environ["MYSQL_PASSWORD"],
    }
    completed = subprocess.run(
        _mysql_command(*extra, username=username),
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=7200,
    )
    if completed.returncode != 0:
        raise ImportFailure("database-command-failed")
    return completed.stdout.decode("utf-8").strip() if completed.stdout else ""


def _assert_empty_target() -> None:
    database = os.environ.get("MYSQL_DATABASE", "openemr")
    tables = set(_run_mysql(database, "--execute=SHOW TABLES").splitlines())
    required = {"documents", "form_encounter", "patient_data", "users"}
    if not required.issubset(tables):
        raise ImportFailure("target-schema-is-not-initialized")
    zero_row_tables = (
        "ar_activity",
        "billing",
        "claims",
        "documents",
        "form_encounter",
        "immunizations",
        "insurance_data",
        "issue_encounter",
        "lists",
        "openemr_postcalendar_events",
        "patient_data",
        "payments",
        "prescriptions",
        "procedure_order",
        "transactions",
    )
    for table in zero_row_tables:
        if table not in tables:
            continue
        # ``table`` can only come from the fixed literal allowlist above.
        value = _run_mysql(database, f"--execute=SELECT COUNT(*) FROM `{table}`")  # nosec B608
        try:
            count = int(value.splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise ImportFailure("target-emptiness-check-failed") from exc
        if count != 0:
            raise ImportFailure("target-is-not-empty")
    users = _run_mysql(database, "--execute=SELECT COUNT(*) FROM `users`")
    try:
        user_count = int(users.splitlines()[-1])
    except (ValueError, IndexError) as exc:
        raise ImportFailure("target-emptiness-check-failed") from exc
    if user_count > 1:
        raise ImportFailure("target-is-not-empty")


def _assert_efs_mutable(mount_root: Path, migration_id: str) -> None:
    """Prove the worker can create and atomically rename sibling directories."""

    if not mount_root.is_dir() or not (mount_root / "default").is_dir():
        raise ImportFailure("target-default-site-missing")
    probe = mount_root / f".openemr-import-probe-{migration_id}"
    renamed = mount_root / f".openemr-import-probe-renamed-{migration_id}"
    if probe.exists() or renamed.exists():
        raise ImportFailure("migration-probe-path-already-exists")
    try:
        probe.mkdir(mode=0o700)
        (probe / "probe").write_bytes(b"openemr-import-write-test\n")
        os.replace(probe, renamed)
    except OSError as exc:
        raise ImportFailure("target-sites-not-writable") from exc
    finally:
        shutil.rmtree(probe, ignore_errors=True)
        shutil.rmtree(renamed, ignore_errors=True)


def _replace_database(sql_path: Path, migration_id: str) -> None:
    database = os.environ.get("MYSQL_DATABASE", "openemr")
    if not re.fullmatch(r"[A-Za-z0-9_]+", database):
        raise ImportFailure("invalid-database-name")
    _run_mysql(
        f"--execute=DROP DATABASE `{database}`; "
        f"CREATE DATABASE `{database}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
    )
    import_username = f"oe_import_{migration_id.removeprefix('import-')}"
    if not re.fullmatch(r"[A-Za-z0-9_]{1,32}", import_username):
        raise ImportFailure("invalid-migration-identity")
    import_password = secrets.token_hex(32)
    account = f"'{import_username}'@'%'"
    setup = (
        f"DROP USER IF EXISTS {account};\n"
        f"CREATE USER {account} IDENTIFIED BY '{import_password}' REQUIRE SSL;\n"
        f"GRANT ALL PRIVILEGES ON `{database}`.* TO {account};\n"
    ).encode("ascii")
    teardown = f"DROP USER IF EXISTS {account};\n".encode("ascii")
    try:
        _run_mysql(stdin=io.BytesIO(setup))
        with sql_path.open("rb") as sql:
            _run_mysql(
                database,
                stdin=sql,
                username=import_username,
                password=import_password,
            )
    finally:
        _run_mysql(stdin=io.BytesIO(teardown))


def _overlay_import_data(import_default: Path, staged_default: Path) -> None:
    for source in import_default.iterdir():
        target = staged_default / source.name
        if target.exists():
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink()
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)


def _restore_target_only_files(source_default: Path, staged_default: Path) -> None:
    if not (source_default / "sqlconf.php").is_file():
        raise ImportFailure("target-sqlconf-missing")
    target_ca = source_default / "documents" / "certificates" / "mysql-ca"
    if target_ca.is_file():
        staged_ca = staged_default / "documents" / "certificates" / "mysql-ca"
        staged_ca.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(target_ca, staged_ca)
    for source in source_default.rglob("*"):
        if not source.is_file() or source.name.lower() not in TARGET_ONLY_FILENAMES:
            continue
        relative = source.relative_to(source_default)
        destination = staged_default / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copy2(source, destination)


def _stage_and_swap_sites(work_default: Path, mount_root: Path, migration_id: str) -> None:
    target_default = mount_root / "default"
    if not target_default.is_dir():
        raise ImportFailure("target-default-site-missing")
    staging_root = mount_root / ".openemr-import-staging" / migration_id
    backup_root = mount_root / ".openemr-import-backup" / migration_id
    if staging_root.exists() or backup_root.exists():
        raise ImportFailure("migration-path-already-exists")
    staged_default = staging_root / "default"
    backup_default = backup_root / "default"
    staging_root.mkdir(parents=True, mode=0o700)
    backup_root.mkdir(parents=True, mode=0o700)
    shutil.copytree(target_default, staged_default)
    _overlay_import_data(work_default, staged_default)
    _restore_target_only_files(target_default, staged_default)
    os.replace(target_default, backup_default)
    try:
        os.replace(staged_default, target_default)
    except BaseException:
        os.replace(backup_default, target_default)
        raise


def _validate_import(mount_root: Path) -> None:
    database = os.environ.get("MYSQL_DATABASE", "openemr")
    tables = _run_mysql(database, "--execute=SHOW TABLES")
    if len(tables.splitlines()) < 50:
        raise ImportFailure("database-validation-failed")
    methods = mount_root / "default" / "documents" / "logs_and_misc" / "methods"
    key_files = (methods / "sixa", methods / "sixb")
    if any(not path.is_file() or path.stat().st_size < 1 for path in key_files):
        raise ImportFailure("site-validation-failed")


def _put_status(
    s3_client: Any,
    *,
    bucket: str,
    migration_id: str,
    status: str,
    phase: str,
    error: str | None = None,
) -> None:
    payload = {
        "schema_version": 1,
        "migration_id": migration_id,
        "status": status,
        "phase": phase,
        "error": error,
    }
    # The bucket's default encryption applies the stack's customer-managed KMS
    # key; a generic aws:kms request header would select the AWS-managed S3 key.
    s3_client.put_object(
        Bucket=bucket,
        Key=f"migrations/{migration_id}/status.json",
        Body=(json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"),
        ContentType="application/json",
    )


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--operation",
        choices=("import", "cleanup"),
        default="import",
    )
    parser.add_argument("--migration-id", required=True)
    parser.add_argument("--source-key")
    parser.add_argument("--source-sha256")
    parser.add_argument("--source-fingerprint")
    parser.add_argument("--recovery-verified", action="store_true")
    parser.add_argument("--delete-site-backup", action="store_true")
    return parser.parse_args()


def _cleanup_site_artifacts(migration_id: str, *, delete_backup: bool) -> None:
    mount_root = Path(os.environ.get("OPENEMR_SITES_MOUNT_ROOT", "/mnt/openemr-sites")).resolve()
    targets = [mount_root / ".openemr-import-staging" / migration_id]
    if delete_backup:
        targets.append(mount_root / ".openemr-import-backup" / migration_id)
    for target in targets:
        try:
            target.resolve().relative_to(mount_root)
        except ValueError as exc:
            raise ImportFailure("unsafe-cleanup-path") from exc
        if target.is_symlink():
            raise ImportFailure("unsafe-cleanup-path")
        if target.exists():
            shutil.rmtree(target)


def main() -> int:
    args = _arguments()
    if not re.fullmatch(r"import-[a-f0-9]{16}", args.migration_id):
        raise SystemExit("invalid migration identifier")
    if args.operation == "cleanup":
        if not args.delete_site_backup:
            raise SystemExit("cleanup requires explicit rollback-copy deletion")
        _phase("cleanup")
        try:
            _cleanup_site_artifacts(
                args.migration_id,
                delete_backup=args.delete_site_backup,
            )
        except ImportFailure as exc:
            print(
                json.dumps(
                    {"phase": "cleanup", "status": "failed", "error": str(exc)},
                    sort_keys=True,
                ),
                flush=True,
            )
            return 1
        _phase("cleanup-complete")
        return 0
    if not args.source_key or not args.source_sha256 or not args.source_fingerprint:
        raise SystemExit("import source arguments are required")
    expected_key = f"migrations/{args.migration_id}/source.tar"
    if args.source_key != expected_key:
        raise SystemExit("invalid staging key")
    bucket = os.environ.get("IMPORT_STAGING_BUCKET", "")
    if not bucket or not args.recovery_verified:
        raise SystemExit("required import safeguards are missing")
    try:
        s3_client = boto3.client("s3")
    except Exception:
        print(
            json.dumps(
                {
                    "phase": "initialization",
                    "status": "failed",
                    "error": "aws-client-initialization-failed",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    work = Path("/work") / args.migration_id
    work.mkdir(mode=0o700)
    source = work / "source.tar"
    phase = "download"
    try:
        _put_status(
            s3_client,
            bucket=bucket,
            migration_id=args.migration_id,
            status="running",
            phase=phase,
        )
        _phase(phase)
        s3_client.download_file(bucket, args.source_key, str(source))
        source_sha = _sha256(source)
        if source_sha != args.source_sha256:
            raise ImportFailure("source-checksum-mismatch")

        phase = "source-validation"
        _phase(phase)
        sql_artifact, sites_artifact, artifact_hashes = _unpack_native_source(source, work)
        component_hashes = {
            "source": f"sha256:{source_sha}",
            "sql": f"sha256:{artifact_hashes['sql']}",
            "sites": f"sha256:{artifact_hashes['sites']}",
        }
        if _canonical_fingerprint(component_hashes) != args.source_fingerprint:
            raise ImportFailure("source-fingerprint-mismatch")
        source.unlink()
        work_default = work / "sites" / "default"
        work_default.mkdir(parents=True, mode=0o700)
        source_version = _validate_and_extract_sites(sites_artifact, work_default)
        sites_artifact.unlink()
        target_version = os.environ.get("TARGET_OPENEMR_VERSION", "")
        if Version(source_version) != Version(target_version):
            raise ImportFailure("source-target-version-mismatch")
        sql = work / "validated.sql"
        _validate_sql(sql_artifact, sql)
        sql_artifact.unlink()

        phase = "target-validation"
        _phase(phase)
        mount_root = Path(os.environ.get("OPENEMR_SITES_MOUNT_ROOT", "/mnt/openemr-sites"))
        _assert_efs_mutable(mount_root, args.migration_id)
        _assert_empty_target()

        phase = "database-import"
        _phase(phase)
        _replace_database(sql, args.migration_id)

        phase = "site-import"
        _phase(phase)
        _stage_and_swap_sites(work_default, mount_root, args.migration_id)

        phase = "post-import-validation"
        _phase(phase)
        _validate_import(mount_root)
        _put_status(
            s3_client,
            bucket=bucket,
            migration_id=args.migration_id,
            status="succeeded",
            phase="complete",
        )
        _phase("complete")
        return 0
    except ImportFailure as exc:
        try:
            _put_status(
                s3_client,
                bucket=bucket,
                migration_id=args.migration_id,
                status="failed",
                phase=phase,
                error=str(exc),
            )
        except Exception:
            pass
        print(
            json.dumps(
                {"phase": phase, "status": "failed", "error": str(exc)},
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    except Exception:
        try:
            _put_status(
                s3_client,
                bucket=bucket,
                migration_id=args.migration_id,
                status="failed",
                phase=phase,
                error="internal-worker-error",
            )
        except Exception:
            pass
        print(
            json.dumps(
                {
                    "phase": phase,
                    "status": "failed",
                    "error": "internal-worker-error",
                },
                sort_keys=True,
            ),
            flush=True,
        )
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
