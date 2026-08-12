"""Small, dependency-free helpers shared by repository maintenance tools."""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

_SUPPORTS_SAFE_OPEN = hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd


class ToolError(RuntimeError):
    """Raised when a maintenance tool cannot safely complete an operation."""


_DENIED_PARTS = {
    ".aws",
    ".azure",
    ".config",
    ".cursor",
    ".docker",
    ".gnupg",
    ".git",
    ".kube",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".ssh",
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
    re.compile(r"(^|[/._-])credentials([._-]|$)", re.IGNORECASE),
    re.compile(
        r"(^|[/._-])credential(?:s(?:[._-]|$)|-(?!rotation(?:[/._-]|$))|[._]|$)",
        re.IGNORECASE,
    ),
    re.compile(r"(^|[/._-])secrets?([._-]|$)", re.IGNORECASE),
    re.compile(r"(^|[/._-])private([._-]?key)?([._-]|$)", re.IGNORECASE),
    re.compile(r"\.(?:der|jks|key|keystore|p12|pem|pfx|pkcs12)$", re.IGNORECASE),
    re.compile(r"\.(?:db|sqlite|sqlite3)$", re.IGNORECASE),
    re.compile(r"(^|/)\.env(?:\.|$)", re.IGNORECASE),
)
_ACCOUNT_ID_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{20,255})\b")
_PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_URL_USERINFO_RE = re.compile(
    r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s:@]+(?::[^/@\s]*)?@",
)
_URL_QUERY_SECRET_RE = re.compile(
    r"(?i)([?&](?:password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"private[_-]?key|client[_-]?secret|credential|authorization|awsaccesskeyid|"
    r"signature|x-amz-(?:credential|signature|security-token))=)[^&#\s]+",
)
_SENSITIVE_KEY_SUFFIX = re.compile(
    r"(?:^|_)(?:password|password_hash|passwd|passphrase|pass|secret|token|credentials?|"
    r"authorization|api_key|access_key|private_key|client_secret|secret_key|"
    r"secret_access_key|security_token)$"
)
_SENSITIVE_ASSIGNMENT_KEY = (
    r"(?:(?i:(?:[a-z0-9]+[_.-])*(?:password(?:[_-]?hash)?|passwd|passphrase|pass|"
    r"secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|"
    r"credentials?|authorization|secret[_-]?access[_-]?key|security[_-]?token))|"
    r"(?:[A-Za-z][A-Za-z0-9]*(?:Password|PasswordHash|Passwd|Passphrase|Secret|Token|"
    r"ApiKey|AccessKey|PrivateKey|ClientSecret|Credentials|Authorization|"
    r"SecretAccessKey|SecurityToken)))"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"""(?m)(?P<prefix>^[ \t]*(?:-\s*)?(?:export[ \t]+)?|[,{]\s*)"""
    rf"""(?P<label>["']?(?P<key>{_SENSITIVE_ASSIGNMENT_KEY})["']?\s*[:=]\s*)"""
    r"""(?P<value>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^,}\]\r\n{\[]+)"""
)
_SECRET_CONTAINER_ASSIGNMENT_RE = re.compile(
    r"""(?m)(?P<prefix>^[ \t]*(?:-\s*)?(?:export[ \t]+)?|[,{]\s*)"""
    rf"""(?P<label>["']?(?P<key>{_SENSITIVE_ASSIGNMENT_KEY})["']?\s*[:=]\s*)"""
    r"""(?P<opening>[{\[])"""
)
_YAML_SECRET_BLOCK_RE = re.compile(
    r"""(?m)^(?P<indent>[ \t]*)(?P<label>(?:-\s*)?["']?"""
    rf"""(?P<key>{_SENSITIVE_ASSIGNMENT_KEY})["']?\s*:\s*)[|>][+-]?\s*(?:#.*)?$"""
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


def is_sensitive_key(value: str) -> bool:
    """Return whether a structured or assignment key denotes a secret value."""

    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    normalized = re.sub(r"[^a-z0-9]+", "_", normalized.lower()).strip("_")
    return _SENSITIVE_KEY_SUFFIX.search(normalized) is not None


def _container_end(value: str, start: int) -> int | None:
    pairs = {"{": "}", "[": "]"}
    stack = [value[start]]
    quote: str | None = None
    escaped = False
    for index in range(start + 1, len(value)):
        character = value[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in pairs:
            stack.append(character)
        elif character in {"}", "]"}:
            if not stack or pairs[stack[-1]] != character:
                return None
            stack.pop()
            if not stack:
                return index + 1
    return None


def _redact_secret_containers(value: str) -> str:
    parts: list[str] = []
    consumed = 0
    search_from = 0
    while match := _SECRET_CONTAINER_ASSIGNMENT_RE.search(value, search_from):
        container_start = match.end() - 1
        container_end = _container_end(value, container_start)
        if container_end is None:
            search_from = match.end()
            continue
        parts.append(value[consumed : match.start()])
        parts.append(f'{match.group("prefix")}{match.group("label")}"<redacted>"')
        parts.append("\n" * value[container_start:container_end].count("\n"))
        consumed = container_end
        search_from = container_end
    parts.append(value[consumed:])
    return "".join(parts)


def redact_text(value: str) -> str:
    """Redact common credentials, secret assignments, and account identifiers."""

    lines = value.splitlines(keepends=True)
    redacted_lines: list[str] = []
    secret_block_indent: int | None = None
    for line in lines:
        content = line.rstrip("\r\n")
        newline = line[len(content) :]
        if secret_block_indent is not None:
            stripped = content.lstrip(" \t")
            indentation = len(content) - len(stripped)
            if not stripped or indentation > secret_block_indent:
                redacted_lines.append(f"{content[:indentation]}<redacted>{newline}" if stripped else line)
                continue
            secret_block_indent = None
        block_match = _YAML_SECRET_BLOCK_RE.match(content)
        if block_match and is_sensitive_key(block_match.group("key")):
            secret_block_indent = len(block_match.group("indent"))
            redacted_lines.append(f'{block_match.group("indent")}{block_match.group("label")}"<redacted>"{newline}')
        else:
            redacted_lines.append(line)
    value = "".join(redacted_lines)
    value = _redact_secret_containers(value)
    value = _PRIVATE_KEY_BLOCK_RE.sub(
        lambda match: "<private-key-redacted>" + "\n" * match.group(0).count("\n"),
        value,
    )
    value = _ACCOUNT_ID_RE.sub("<account-id>", value)
    value = _AWS_ACCESS_KEY_RE.sub("<aws-access-key>", value)
    value = _GITHUB_TOKEN_RE.sub("<github-token>", value)
    value = _URL_USERINFO_RE.sub(r"\1<redacted>@", value)
    value = _URL_QUERY_SECRET_RE.sub(r"\1<redacted>", value)

    def redact_assignment(match: re.Match[str]) -> str:
        if not is_sensitive_key(match.group("key")):
            return match.group(0)
        return f'{match.group("prefix")}{match.group("label")}"<redacted>"'

    return _SECRET_ASSIGNMENT_RE.sub(redact_assignment, value)


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
    if not root.is_dir():
        raise ToolError("Repository root is not a directory")
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

    root = root.resolve()
    path = resolve_repo_path(
        root,
        requested,
        allowed_extensions=allowed_extensions,
        require_file=False,
    )
    relative = path.relative_to(root)
    if not relative.parts:
        raise ToolError("Requested path is not a regular file")
    if not _SUPPORTS_SAFE_OPEN:
        raise ToolError("This platform does not support safe descriptor-relative repository reads")

    close_on_exec = getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | close_on_exec
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | close_on_exec
    descriptors: list[int] = []
    try:
        descriptors.append(os.open(root, directory_flags))
        for part in relative.parts[:-1]:
            descriptors.append(os.open(part, directory_flags, dir_fd=descriptors[-1]))
        descriptors.append(os.open(relative.parts[-1], file_flags, dir_fd=descriptors[-1]))

        information = os.fstat(descriptors[-1])
        if not stat.S_ISREG(information.st_mode):
            raise ToolError("Requested path is not a regular file")
        if information.st_size > max_bytes:
            raise ToolError(f"File is {information.st_size} bytes; limit is {max_bytes} bytes")

        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(descriptors[-1], min(65_536, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > max_bytes:
            raise ToolError(f"File exceeded the {max_bytes}-byte limit while being read")
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ToolError("Requested file is not valid UTF-8 text") from exc
    except OSError as exc:
        raise ToolError(f"Unable to safely read requested file: {exc.strerror or exc}") from exc
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                # A close error must not prevent attempts on the remaining
                # descriptors or replace the primary read result/error.
                pass
