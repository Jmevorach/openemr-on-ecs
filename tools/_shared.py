"""Small, dependency-free helpers shared by repository maintenance tools."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


class ToolError(RuntimeError):
    """Raised when a maintenance tool cannot safely complete an operation."""


@dataclass(frozen=True)
class CommandResult:
    """Structured result from a bounded local command."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float

    @property
    def ok(self) -> bool:
        """Return whether the command exited successfully."""

        return self.returncode == 0


_DENIED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".aws",
    ".live-e2e",
    ".openemr-import",
    "__pycache__",
    "build",
    "cdk.out",
    "coverage",
    "dist",
    "e2e-results",
    "htmlcov",
    "migration-bundles",
    "node_modules",
    "tmp",
}
_DENIED_FILE_PATTERNS = (
    re.compile(r"(^|[._-])credentials?([._-]|$)", re.IGNORECASE),
    re.compile(r"(^|[._-])secrets?([._-]|$)", re.IGNORECASE),
    re.compile(r"(^|[._-])private([._-]?key)?([._-]|$)", re.IGNORECASE),
    re.compile(r"\.(?:der|jks|key|keystore|p12|pem|pfx|pkcs12)$", re.IGNORECASE),
    re.compile(r"\.(?:db|sqlite|sqlite3)$", re.IGNORECASE),
    re.compile(r"(^|/)\.env(?:\.|$)", re.IGNORECASE),
)
_ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_AUTHORITY_CREDENTIAL_RE = re.compile(r"(?i)([a-z][a-z0-9+.-]*://[^:/@\s]+:)[^@\s]+(@)")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?im)^(\s*["']?[a-z0-9_.-]*(?:password|passwd|secret|token|access[_-]?key|private[_-]?key)"""
    r"""[a-z0-9_.-]*["']?\s*[:=]\s*).+$"""
)


def repository_root(start: Path | None = None) -> Path:
    """Find the repository root without depending on the caller's working directory."""

    current = (start or Path(__file__)).resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / "cdk.json").is_file() and (candidate / "openemr_ecs").is_dir():
            return candidate
    raise ToolError(f"Unable to locate repository root from {current}")


def ensure_owner_only_directory(
    path: Path,
    *,
    parents: bool = False,
    exist_ok: bool = True,
    label: str = "state",
) -> None:
    """Create or validate a non-symlinked directory with mode 0700."""

    if path.is_symlink():
        raise ToolError(f"Refusing symlinked {label} directory: {path.name}")
    path.mkdir(parents=parents, exist_ok=exist_ok, mode=0o700)
    if not path.is_dir() or path.is_symlink():
        raise ToolError(f"{label.capitalize()} path is not a private directory: {path.name}")
    os.chmod(path, 0o700)


def utc_now() -> str:
    """Return a normalized UTC timestamp suitable for generated records."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    """Serialize a value deterministically."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(value: Any, *, length: int = 16) -> str:
    """Return a short deterministic SHA-256 fingerprint."""

    if length < 8 or length > 64:
        raise ValueError("fingerprint length must be between 8 and 64")
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:length]


def hash_account_id(account_id: str) -> str:
    """Return a stable, non-reversible account label for reports."""

    if not re.fullmatch(r"\d{12}", account_id):
        raise ToolError("AWS account ID must contain exactly 12 digits")
    return f"sha256:{hashlib.sha256(account_id.encode('ascii')).hexdigest()[:12]}"


def redact_text(value: str) -> str:
    """Redact common secret assignments and 12-digit account identifiers."""

    value = _ACCOUNT_ID_RE.sub("<account-id>", value)
    value = _AWS_ACCESS_KEY_RE.sub("<aws-access-key>", value)
    value = _AUTHORITY_CREDENTIAL_RE.sub(r"\1<redacted>\2", value)
    return _SECRET_ASSIGNMENT_RE.sub(r"\1<redacted>", value)


def is_secret_like_path(path: Path) -> bool:
    """Return whether a repository-relative path is unsafe to expose."""

    lowered_parts = {part.lower() for part in path.parts}
    if lowered_parts & _DENIED_PARTS:
        return True
    normalized = path.as_posix()
    return any(pattern.search(normalized) for pattern in _DENIED_FILE_PATTERNS)


def resolve_repo_path(
    root: Path,
    requested: str | Path,
    *,
    allowed_extensions: Iterable[str] | None = None,
    require_file: bool = True,
) -> Path:
    """Resolve a path while enforcing repository containment and deny rules."""

    root = root.resolve()
    requested_path = Path(requested)
    lexical_candidate = requested_path if requested_path.is_absolute() else root / requested_path
    try:
        lexical_relative = lexical_candidate.relative_to(root)
    except ValueError as exc:
        raise ToolError("Path escapes the repository root") from exc
    if ".." in lexical_relative.parts:
        raise ToolError("Path escapes the repository root")
    current = root
    for part in lexical_relative.parts:
        current /= part
        if current.is_symlink():
            raise ToolError("Symlinks are excluded by the repository read policy")
    candidate = lexical_candidate.resolve()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ToolError("Path escapes the repository root") from exc
    if is_secret_like_path(relative):
        raise ToolError("Path is excluded by the repository read policy")
    if allowed_extensions is not None:
        allowed = {extension.lower() for extension in allowed_extensions}
        if candidate.suffix.lower() not in allowed:
            raise ToolError(f"File extension {candidate.suffix or '<none>'} is not allowed")
    if require_file and not candidate.is_file():
        raise ToolError("Requested path is not a regular file")
    return candidate


def safe_read_text(
    root: Path,
    requested: str | Path,
    *,
    max_bytes: int = 256_000,
    allowed_extensions: Iterable[str] | None = None,
) -> str:
    """Read a bounded, policy-approved repository text file."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    path = resolve_repo_path(root, requested, allowed_extensions=allowed_extensions)
    size = path.stat().st_size
    if size > max_bytes:
        raise ToolError(f"File is {size} bytes; limit is {max_bytes} bytes")
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ToolError("Requested file is not valid UTF-8 text") from exc


def atomic_write_text(path: Path, content: str) -> None:
    """Atomically replace a UTF-8 text file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, value: Any) -> None:
    """Atomically replace a deterministic JSON file."""

    atomic_write_text(path, f"{json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)}\n")


def run_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: float,
    env: Mapping[str, str] | None = None,
    umask: int | None = None,
) -> CommandResult:
    """Run a local command with no shell and a hard timeout."""

    if not argv:
        raise ValueError("argv cannot be empty")
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    started = time.monotonic()
    process = subprocess.Popen(
        [str(part) for part in argv],
        cwd=cwd,
        env={**os.environ, **dict(env or {})},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        umask=-1 if umask is None else umask,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise ToolError(f"Command timed out after {timeout_seconds:g}s: {' '.join(argv)}") from exc
    duration = time.monotonic() - started
    return CommandResult(
        argv=tuple(str(part) for part in argv),
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_seconds=duration,
    )
