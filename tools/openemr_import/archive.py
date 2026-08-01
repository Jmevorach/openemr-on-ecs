"""Defensive archive inspection without extracting patient data."""

from __future__ import annotations

import re
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import IO, Callable, TypedDict

from tools._shared import ToolError

from .models import ArchiveLimits, SiteInventory

_ARCHIVE_SUFFIXES = (
    ".7z",
    ".bz2",
    ".gz",
    ".rar",
    ".tar",
    ".tgz",
    ".xz",
    ".zip",
)
_EXECUTABLE_SUFFIXES = (".cgi", ".js", ".php", ".pl", ".py", ".sh")
_IMPORTED_DIRECTORY_ROOTS = {"LBF", "documents", "images"}
_IMPORTED_TOP_LEVEL_FILES = {
    "clickoptions.txt",
    "faxcover.txt",
    "faxtitle.eps",
    "referral_template.html",
}
_REQUIRED_DRIVE_KEY_FILES = {"sevena", "sevenb"}
_VERSION_FIELD = re.compile(rb"\$(v_major|v_minor|v_patch|v_tag|v_realpatch)\s*=\s*['\"]([^'\"]*)['\"]")


@dataclass(frozen=True)
class ArchiveScan:
    """Aggregate facts returned by a safe archive scan."""

    expanded_bytes: int
    member_count: int
    sites: tuple[SiteInventory, ...]
    openemr_version: str | None
    ignored_application_file_count: int
    nested_archive_count: int
    custom_code_detected: bool
    unsupported_content: tuple[str, ...]
    manual_review: tuple[str, ...]


@dataclass
class _MutableSite:
    has_sqlconf: bool = False
    has_documents: bool = False
    document_count: int = 0
    drive_key_files: set[str] = field(default_factory=set)
    certificate_count: int = 0
    edi_file_count: int = 0
    executable_file_count: int = 0


class _Facts(TypedDict):
    openemr_version: str | None
    ignored_application_file_count: int
    nested_archive_count: int
    custom_code_detected: bool


def _safe_member_name(raw_name: str) -> PurePosixPath:
    if "\x00" in raw_name or "\\" in raw_name:
        raise ToolError("Archive contains an unsafe member path")
    name = raw_name
    while name.startswith("./"):
        name = name[2:]
    if not name or name.startswith("/") or re.match(r"^[A-Za-z]:", name):
        raise ToolError("Archive contains an absolute or empty member path")
    path = PurePosixPath(name)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise ToolError("Archive contains a path traversal component")
    return path


def _parse_version(content: bytes) -> str | None:
    fields = {
        key.decode("ascii"): value.decode("utf-8", errors="strict").strip()
        for key, value in _VERSION_FIELD.findall(content)
    }
    if not all(field in fields for field in ("v_major", "v_minor", "v_patch")):
        return None
    version = f"{fields['v_major']}.{fields['v_minor']}.{fields['v_patch']}"
    realpatch = fields.get("v_realpatch", "")
    if realpatch and realpatch != "0":
        version = f"{version}.{realpatch}"
    tag = fields.get("v_tag", "")
    if tag:
        version = f"{version}{tag}"
    return version


def _record_member(
    *,
    path: PurePosixPath,
    is_directory: bool,
    size: int,
    mode: int,
    read_small_file: Callable[[], bytes],
    sites: dict[str, _MutableSite],
    facts: _Facts,
) -> None:
    parts = path.parts
    if not is_directory and path.name.lower().endswith(_ARCHIVE_SUFFIXES):
        facts["nested_archive_count"] += 1

    if parts[0] != "sites":
        if not is_directory:
            facts["ignored_application_file_count"] += 1
        if path.as_posix() == "version.php" and size <= 64 * 1024:
            facts["openemr_version"] = _parse_version(read_small_file())
        normalized = path.as_posix().lower()
        if "/custom_modules/" in f"/{normalized}/" or normalized.startswith(("custom/", "modules/custom/")):
            facts["custom_code_detected"] = True
        return

    if len(parts) < 2:
        return
    if len(parts) == 2 and not is_directory:
        return
    site_id = parts[1]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", site_id):
        raise ToolError("Archive contains an invalid OpenEMR site identifier")
    site = sites.setdefault(site_id, _MutableSite())
    relative = parts[2:]
    if relative == ("sqlconf.php",):
        site.has_sqlconf = True
        return
    if relative and relative[0] == "documents":
        site.has_documents = True
        if not is_directory:
            site.document_count += 1
            lowered = tuple(part.lower() for part in relative)
            if "certificates" in lowered:
                site.certificate_count += 1
            if any(part in {"edi", "era", "edihistory"} for part in lowered):
                site.edi_file_count += 1
            if (
                lowered[:3] == ("documents", "logs_and_misc", "methods")
                and len(lowered) == 4
                and lowered[3] in _REQUIRED_DRIVE_KEY_FILES
                and size > 0
            ):
                site.drive_key_files.add(lowered[3])

    import_candidate = bool(
        relative
        and (
            relative[0] in _IMPORTED_DIRECTORY_ROOTS
            or (len(relative) == 1 and relative[0] in _IMPORTED_TOP_LEVEL_FILES)
        )
    )
    if not is_directory and import_candidate:
        executable = bool(mode & 0o111) or path.name.lower().endswith(_EXECUTABLE_SUFFIXES)
        if executable:
            site.executable_file_count += 1
            facts["custom_code_detected"] = True


def _finalize(
    *,
    expanded_bytes: int,
    member_count: int,
    sites: dict[str, _MutableSite],
    facts: _Facts,
) -> ArchiveScan:
    inventory = tuple(
        SiteInventory(
            site_id=site_id,
            has_sqlconf=site.has_sqlconf,
            has_documents=site.has_documents,
            document_count=site.document_count,
            has_encryption_keys=_REQUIRED_DRIVE_KEY_FILES.issubset(site.drive_key_files),
            certificate_count=site.certificate_count,
            edi_file_count=site.edi_file_count,
            executable_file_count=site.executable_file_count,
        )
        for site_id, site in sorted(sites.items())
    )
    unsupported: list[str] = []
    manual_review: list[str] = []
    if not inventory:
        unsupported.append("No canonical sites/<site-id> tree was found")
    for site in inventory:
        if not site.has_sqlconf:
            unsupported.append(f"Site {site.site_id!r} is missing its sqlconf.php marker")
        if not site.has_documents:
            unsupported.append(f"Site {site.site_id!r} is missing its documents directory")
        if not site.has_encryption_keys:
            manual_review.append(f"Site {site.site_id!r} does not contain both sevena and sevenb encryption keys")
        if site.executable_file_count:
            manual_review.append(f"Site {site.site_id!r} contains executable or script-like files")
    if facts["custom_code_detected"]:
        manual_review.append(
            "Custom executable application content was detected and will not be imported automatically"
        )
    return ArchiveScan(
        expanded_bytes=expanded_bytes,
        member_count=member_count,
        sites=inventory,
        openemr_version=facts["openemr_version"],
        ignored_application_file_count=facts["ignored_application_file_count"],
        nested_archive_count=facts["nested_archive_count"],
        custom_code_detected=facts["custom_code_detected"],
        unsupported_content=tuple(unsupported),
        manual_review=tuple(manual_review),
    )


def _check_common_limits(
    *,
    path: PurePosixPath,
    size: int,
    compressed_size: int,
    seen: set[str],
    casefolded: set[str],
    totals: dict[str, int],
    limits: ArchiveLimits,
) -> None:
    normalized = path.as_posix()
    folded = normalized.casefold()
    if normalized in seen:
        raise ToolError("Archive contains duplicate member paths")
    if folded in casefolded:
        raise ToolError("Archive contains case-colliding member paths")
    seen.add(normalized)
    casefolded.add(folded)
    totals["members"] += 1
    totals["bytes"] += size
    if totals["members"] > limits.max_members:
        raise ToolError("Archive member-count limit exceeded")
    if size > limits.max_member_bytes:
        raise ToolError("Archive member-size limit exceeded")
    if totals["bytes"] > limits.max_expanded_bytes:
        raise ToolError("Archive expanded-size limit exceeded")
    if compressed_size > 0 and size > compressed_size * limits.max_compression_ratio:
        raise ToolError("Archive compression-ratio limit exceeded")


def _scan_tar(fileobj: IO[bytes], limits: ArchiveLimits) -> ArchiveScan:
    sites: dict[str, _MutableSite] = {}
    facts: _Facts = {
        "openemr_version": None,
        "ignored_application_file_count": 0,
        "nested_archive_count": 0,
        "custom_code_detected": False,
    }
    seen: set[str] = set()
    casefolded: set[str] = set()
    totals = {"members": 0, "bytes": 0}
    try:
        with tarfile.open(fileobj=fileobj, mode="r:*") as archive:
            for member in archive:
                if member.isdir() and member.name in {".", "./"}:
                    continue
                path = _safe_member_name(member.name)
                if not (member.isfile() or member.isdir()):
                    raise ToolError("Archive links, devices, FIFOs, and special files are not allowed")
                _check_common_limits(
                    path=path,
                    size=member.size,
                    compressed_size=0,
                    seen=seen,
                    casefolded=casefolded,
                    totals=totals,
                    limits=limits,
                )

                def read_small_file() -> bytes:
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        return b""
                    return extracted.read(64 * 1024 + 1)

                _record_member(
                    path=path,
                    is_directory=member.isdir(),
                    size=member.size,
                    mode=member.mode,
                    read_small_file=read_small_file,
                    sites=sites,
                    facts=facts,
                )
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ToolError("Malformed or unsupported tar archive") from exc
    return _finalize(
        expanded_bytes=totals["bytes"],
        member_count=totals["members"],
        sites=sites,
        facts=facts,
    )


def _scan_zip(fileobj: IO[bytes], limits: ArchiveLimits) -> ArchiveScan:
    sites: dict[str, _MutableSite] = {}
    facts: _Facts = {
        "openemr_version": None,
        "ignored_application_file_count": 0,
        "nested_archive_count": 0,
        "custom_code_detected": False,
    }
    seen: set[str] = set()
    casefolded: set[str] = set()
    totals = {"members": 0, "bytes": 0}
    try:
        with zipfile.ZipFile(fileobj) as archive:
            for member in archive.infolist():
                path = _safe_member_name(member.filename)
                mode = member.external_attr >> 16
                if member.flag_bits & 0x1:
                    raise ToolError("Encrypted zip members are not supported")
                if stat.S_ISLNK(mode):
                    raise ToolError("Archive symlinks are not allowed")
                _check_common_limits(
                    path=path,
                    size=member.file_size,
                    compressed_size=member.compress_size,
                    seen=seen,
                    casefolded=casefolded,
                    totals=totals,
                    limits=limits,
                )

                def read_small_file() -> bytes:
                    with archive.open(member) as handle:
                        return handle.read(64 * 1024 + 1)

                _record_member(
                    path=path,
                    is_directory=member.is_dir(),
                    size=member.file_size,
                    mode=mode,
                    read_small_file=read_small_file,
                    sites=sites,
                    facts=facts,
                )
    except (zipfile.BadZipFile, OSError) as exc:
        raise ToolError("Malformed or unsupported zip archive") from exc
    return _finalize(
        expanded_bytes=totals["bytes"],
        member_count=totals["members"],
        sites=sites,
        facts=facts,
    )


def scan_sites_archive(
    fileobj: IO[bytes],
    *,
    format_hint: str,
    limits: ArchiveLimits,
) -> ArchiveScan:
    """Inspect one site archive without extracting it."""

    if format_hint.lower().endswith(".zip"):
        return _scan_zip(fileobj, limits)
    return _scan_tar(fileobj, limits)
