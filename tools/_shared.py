"""Small, dependency-free helpers shared by repository maintenance tools."""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


class ToolError(RuntimeError):
    """Raised when a maintenance tool cannot safely complete an operation."""


_DENIED_PARTS = {
    ".aws",
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "cdk.out",
    "coverage",
    "dist",
    "htmlcov",
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
_URL_USERINFO_RE = re.compile(
    r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/@\s]*)?@",
)
_URL_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|authorization)=)[^&#\s]+",
)
_SECRET_KEY = (
    r"[a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|authorization)[a-z0-9_.-]*"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    rf"""(?im)(^|[{{,]\s*)(["']?{_SECRET_KEY}["']?\s*[:=]\s*)"""
    r"""(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,}\]\r\n]+)"""
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


def utc_now() -> str:
    """Return a normalized UTC timestamp suitable for generated records."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_text(value: str) -> str:
    """Redact common credentials, secret assignments, and account identifiers."""

    value = _ACCOUNT_ID_RE.sub("<account-id>", value)
    value = _AWS_ACCESS_KEY_RE.sub("<aws-access-key>", value)
    value = _URL_USERINFO_RE.sub(r"\1<redacted>@", value)
    value = _URL_QUERY_SECRET_RE.sub(r"\1<redacted>", value)
    return _SECRET_ASSIGNMENT_RE.sub(r'\1\2"<redacted>"', value)


def is_secret_like_path(path: Path) -> bool:
    """Return whether a repository-relative path is unsafe to expose."""

    lowered_parts = {part.lower() for part in path.parts}
    if lowered_parts & _DENIED_PARTS:
        return True
    return any(pattern.search(path.name) for pattern in _DENIED_FILE_PATTERNS)


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
