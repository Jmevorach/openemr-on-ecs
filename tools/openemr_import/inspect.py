"""Offline source adapters and full pre-mutation import inspection."""

from __future__ import annotations

import gzip
import hashlib
import json
import tarfile
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Iterator, cast

from packaging.version import InvalidVersion, Version

from tools._shared import ToolError, fingerprint

from .archive import _safe_member_name, scan_sites_archive
from .models import SCHEMA_VERSION, ArchiveLimits, SourceInspection

_SQL_NAMES = ("openemr.sql.gz", "openemr.sql")
# Execution intentionally supports only OpenEMR's canonical native-backup member.
# Keeping inspection aligned prevents a plan from passing offline and then failing
# only after the target service has been stopped.
_SITE_NAMES = ("openemr.tar.gz",)


@dataclass(frozen=True)
class _Artifacts:
    source_kind: str
    source_bytes: int
    source_sha256: str
    sql: IO[bytes]
    sql_name: str
    sql_bytes: int
    sql_sha256: str
    sites: IO[bytes]
    sites_name: str
    sites_bytes: int
    sites_sha256: str
    manifest_version: str | None = None
    extra_member_count: int = 0


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_bounded(source: IO[bytes], destination: IO[bytes], limit: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = source.read(1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ToolError("Nested backup artifact exceeds the configured size limit")
        digest.update(chunk)
        destination.write(chunk)
    destination.seek(0)
    return total, digest.hexdigest()


def _resolve_manifest_artifact(directory: Path, value: object) -> tuple[Path, str]:
    if not isinstance(value, dict):
        raise ToolError("Import manifest artifact entries must be objects")
    requested = value.get("path")
    expected_sha = value.get("sha256")
    if not isinstance(requested, str) or not isinstance(expected_sha, str):
        raise ToolError("Import manifest artifacts require path and sha256 strings")
    relative = Path(requested)
    if relative.is_absolute() or ".." in relative.parts:
        raise ToolError("Import manifest artifact path escapes the source directory")
    path = (directory / relative).resolve()
    try:
        path.relative_to(directory.resolve())
    except ValueError as exc:
        raise ToolError("Import manifest artifact path escapes the source directory") from exc
    if path.is_symlink() or not path.is_file():
        raise ToolError("Import manifest artifact is not a regular local file")
    actual_sha = _sha256_file(path)
    if actual_sha.lower() != expected_sha.lower():
        raise ToolError("Import manifest artifact checksum does not match")
    return path, actual_sha


def _directory_artifact_paths(
    directory: Path,
) -> tuple[str, Path, str, Path, str | None]:
    manifest_path = directory / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ToolError("Import manifest is not valid UTF-8 JSON") from exc
        if manifest.get("schema_version") != 1:
            raise ToolError("Unsupported import manifest schema version")
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict):
            raise ToolError("Import manifest requires an artifacts object")
        sql, _ = _resolve_manifest_artifact(directory, artifacts.get("sql"))
        sites, _ = _resolve_manifest_artifact(directory, artifacts.get("sites"))
        source_version = manifest.get("source_openemr_version")
        if source_version is not None and not isinstance(source_version, str):
            raise ToolError("Manifest source_openemr_version must be a string")
        return "manifest-bundle", sql, sites.name, sites, source_version

    sql_candidates = [directory / name for name in _SQL_NAMES if (directory / name).is_file()]
    site_candidates = [directory / name for name in _SITE_NAMES if (directory / name).is_file()]
    if len(sql_candidates) != 1 or len(site_candidates) != 1:
        raise ToolError("Directory sources require exactly one openemr.sql[.gz] and one supported sites archive")
    sql = sql_candidates[0]
    sites = site_candidates[0]
    if sql.is_symlink() or sites.is_symlink():
        raise ToolError("Import source artifacts may not be symlinks")
    return "sql-and-sites", sql, sites.name, sites, None


@contextmanager
def _from_directory(
    directory: Path,
    limits: ArchiveLimits,
) -> Iterator[_Artifacts]:
    source_kind, sql_path, sites_name, sites_path, manifest_version = _directory_artifact_paths(directory)
    sql_size = sql_path.stat().st_size
    sites_size = sites_path.stat().st_size
    if sql_size > limits.max_nested_archive_bytes or sites_size > limits.max_nested_archive_bytes:
        raise ToolError("Import source artifact exceeds the configured compressed-size limit")
    sql_sha = _sha256_file(sql_path)
    sites_sha = _sha256_file(sites_path)
    source_sha = hashlib.sha256(f"{sql_sha}:{sites_sha}".encode("ascii")).hexdigest()
    with sql_path.open("rb") as sql_handle, sites_path.open("rb") as sites_handle:
        yield _Artifacts(
            source_kind=source_kind,
            source_bytes=sql_size + sites_size,
            source_sha256=source_sha,
            sql=sql_handle,
            sql_name=sql_path.name,
            sql_bytes=sql_size,
            sql_sha256=sql_sha,
            sites=sites_handle,
            sites_name=sites_name,
            sites_bytes=sites_size,
            sites_sha256=sites_sha,
            manifest_version=manifest_version,
        )


@contextmanager
def _from_native_backup(path: Path, limits: ArchiveLimits) -> Iterator[_Artifacts]:
    source_size = path.stat().st_size
    if source_size > limits.max_expanded_bytes:
        raise ToolError("Native backup exceeds the configured source-size limit")
    source_sha = _sha256_file(path)
    sql_spool = tempfile.SpooledTemporaryFile(max_size=32 * 1024**2)
    sites_spool = tempfile.SpooledTemporaryFile(max_size=32 * 1024**2)
    selected: dict[str, tuple[int, str, str]] = {}
    extras = 0
    seen: set[str] = set()
    casefolded: set[str] = set()
    try:
        try:
            archive = tarfile.open(path, mode="r:*")
        except (tarfile.TarError, OSError) as exc:
            raise ToolError("Source file is not a supported native OpenEMR backup") from exc
        with archive:
            members = 0
            expanded = 0
            for member in archive:
                if member.isdir() and member.name in {".", "./"}:
                    continue
                member_path = _safe_member_name(member.name)
                normalized = member_path.as_posix()
                folded = normalized.casefold()
                if normalized in seen or folded in casefolded:
                    raise ToolError("Native backup contains duplicate or case-colliding paths")
                seen.add(normalized)
                casefolded.add(folded)
                members += 1
                expanded += member.size
                if members > limits.max_members or expanded > limits.max_expanded_bytes:
                    raise ToolError("Native backup archive limits exceeded")
                if not member.isfile():
                    if member.isdir():
                        continue
                    raise ToolError("Native backup contains a link or special file")
                basename = member_path.name
                target: IO[bytes] | None = None
                artifact_kind = ""
                if len(member_path.parts) == 1 and basename in _SQL_NAMES:
                    target = sql_spool
                    artifact_kind = "sql"
                elif len(member_path.parts) == 1 and basename in _SITE_NAMES:
                    target = sites_spool
                    artifact_kind = "sites"
                else:
                    extras += 1
                    continue
                if artifact_kind in selected:
                    raise ToolError("Native backup contains duplicate required artifacts")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ToolError("Native backup artifact could not be read")
                assert target is not None
                size, sha = _copy_bounded(
                    extracted,
                    target,
                    limits.max_nested_archive_bytes,
                )
                selected[artifact_kind] = (size, sha, basename)
        if set(selected) != {"sql", "sites"}:
            raise ToolError("Native backup must contain openemr.sql[.gz] and openemr.tar.gz")
        yield _Artifacts(
            source_kind="native-openemr-backup",
            source_bytes=source_size,
            source_sha256=source_sha,
            sql=sql_spool,
            sql_name=selected["sql"][2],
            sql_bytes=selected["sql"][0],
            sql_sha256=selected["sql"][1],
            sites=sites_spool,
            sites_name=selected["sites"][2],
            sites_bytes=selected["sites"][0],
            sites_sha256=selected["sites"][1],
            extra_member_count=extras,
        )
    finally:
        sql_spool.close()
        sites_spool.close()


def _inspect_sql(
    handle: IO[bytes],
    *,
    name: str,
    compressed_bytes: int,
    limits: ArchiveLimits,
) -> tuple[str, int, bool]:
    handle.seek(0)
    compressed = name.lower().endswith(".gz")
    stream = handle
    try:
        if compressed:
            stream = cast(IO[bytes], gzip.GzipFile(fileobj=handle, mode="rb"))
        total = 0
        prefix = bytearray()
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > limits.max_expanded_bytes:
                raise ToolError("SQL dump expanded-size limit exceeded")
            if len(prefix) < 2 * 1024 * 1024:
                prefix.extend(chunk[: 2 * 1024 * 1024 - len(prefix)])
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise ToolError("SQL dump compression is malformed") from exc
    finally:
        handle.seek(0)
    if compressed and compressed_bytes and total > (compressed_bytes * limits.max_compression_ratio):
        raise ToolError("SQL dump compression-ratio limit exceeded")
    sample = bytes(prefix).lower()
    if b"\x00" in sample:
        raise ToolError("SQL dump appears to contain binary data")
    has_mysql_header = b"mysql dump" in sample or b"mariadb dump" in sample
    has_sql_structure = b"create table" in sample or b"insert into" in sample or b"lock tables" in sample
    if not has_mysql_header or not has_sql_structure:
        raise ToolError("SQL artifact is not a recognizable MySQL or MariaDB dump")
    database_type = "mariadb" if b"mariadb" in sample else "mysql"
    return database_type, total, compressed


def _normalized_version(
    detected: str | None,
    declared: str | None,
) -> str | None:
    if detected and declared:
        try:
            if Version(detected) != Version(declared):
                raise ToolError("Declared source version does not match version.php in the site archive")
        except InvalidVersion as exc:
            raise ToolError("Source OpenEMR version is not valid semantic version data") from exc
    value = detected or declared
    if value is None:
        return None
    try:
        parsed = Version(value)
    except InvalidVersion as exc:
        raise ToolError("Source OpenEMR version is not a valid version") from exc
    if parsed.is_prerelease or parsed.is_devrelease:
        raise ToolError("Prerelease OpenEMR sources are not supported")
    return str(parsed)


def inspect_source(
    source: Path,
    *,
    source_version: str | None = None,
    limits: ArchiveLimits | None = None,
) -> SourceInspection:
    """Fully inspect a source without extracting or mutating it."""

    limits = limits or ArchiveLimits()
    source = source.expanduser()
    if source.is_symlink():
        raise ToolError("Import source may not be a symlink")
    if not source.exists():
        raise ToolError("Import source does not exist")
    adapter = _from_directory(source, limits) if source.is_dir() else _from_native_backup(source, limits)
    with adapter as artifacts:
        database_type, sql_expanded_bytes, sql_compressed = _inspect_sql(
            artifacts.sql,
            name=artifacts.sql_name,
            compressed_bytes=artifacts.sql_bytes,
            limits=limits,
        )
        artifacts.sites.seek(0)
        archive_scan = scan_sites_archive(
            artifacts.sites,
            format_hint=artifacts.sites_name,
            limits=limits,
        )
        artifacts.sites.seek(0)
        if (
            artifacts.sites_name.lower().endswith((".gz", ".tgz", ".zip"))
            and artifacts.sites_bytes
            and archive_scan.expanded_bytes > artifacts.sites_bytes * limits.max_compression_ratio
        ):
            raise ToolError("Sites archive compression-ratio limit exceeded")
        version = _normalized_version(
            archive_scan.openemr_version,
            source_version or artifacts.manifest_version,
        )
        unsupported = list(archive_scan.unsupported_content)
        manual_review = list(archive_scan.manual_review)
        if artifacts.extra_member_count:
            manual_review.append("Native backup contained additional top-level artifacts that will be ignored")
        if artifacts.source_kind == "native-openemr-backup" and archive_scan.openemr_version is None:
            unsupported.append(
                "Native backup must contain version.php; --source-version cannot " "authorize automatic execution"
            )
        if version is None:
            unsupported.append("Source OpenEMR version was not detected")
        component_hashes = {
            "source": f"sha256:{artifacts.source_sha256}",
            "sql": f"sha256:{artifacts.sql_sha256}",
            "sites": f"sha256:{artifacts.sites_sha256}",
        }
        source_fingerprint = fingerprint(component_hashes, length=32)
        return SourceInspection(
            schema_version=SCHEMA_VERSION,
            source_kind=artifacts.source_kind,
            source_fingerprint=source_fingerprint,
            source_bytes=artifacts.source_bytes,
            source_openemr_version=version,
            database_type=database_type,
            sql_compressed=sql_compressed,
            sql_bytes=sql_expanded_bytes,
            sites_archive_bytes=artifacts.sites_bytes,
            expanded_site_bytes=archive_scan.expanded_bytes,
            archive_member_count=archive_scan.member_count,
            sites=archive_scan.sites,
            ignored_application_file_count=archive_scan.ignored_application_file_count,
            nested_archive_count=archive_scan.nested_archive_count,
            custom_code_detected=archive_scan.custom_code_detected,
            unsupported_content=tuple(unsupported),
            manual_review=tuple(manual_review),
            checksums=component_hashes,
        )
