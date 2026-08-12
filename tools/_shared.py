"""Small, dependency-free helpers shared by repository maintenance tools."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
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


def ensure_owner_only_directory(
    path: Path,
    *,
    parents: bool = False,
    exist_ok: bool = True,
    label: str = "state",
) -> None:
    """Create or validate an owner-only directory without following symlinks."""

    descriptor = _open_owner_only_directory(
        path,
        parents=parents,
        exist_ok=exist_ok,
        label=label,
    )
    os.close(descriptor)


def _open_owner_only_directory(
    path: Path,
    *,
    parents: bool,
    exist_ok: bool = True,
    label: str,
) -> int:
    if not _SUPPORTS_SAFE_OPEN:
        raise ToolError(f"This platform cannot safely open the {label} directory")
    absolute = path.expanduser()
    if not absolute.is_absolute():
        absolute = Path.cwd() / absolute
    parts = absolute.parts
    if not parts or not absolute.anchor:
        raise ToolError(f"Invalid {label} directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(absolute.anchor, flags)
    created_final = False
    try:
        for index, part in enumerate(parts[1:]):
            final = index == len(parts[1:]) - 1
            try:
                child = os.open(part, flags, dir_fd=descriptor)
                if final and not exist_ok:
                    os.close(child)
                    raise FileExistsError(path)
            except FileNotFoundError:
                if not final and not parents:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
                if final:
                    created_final = True
            os.close(descriptor)
            descriptor = child
        information = os.fstat(descriptor)
        if not stat.S_ISDIR(information.st_mode) or information.st_uid != os.geteuid():
            raise ToolError(f"{label.capitalize()} path is not an owned private directory")
        if not created_final and not exist_ok:
            raise FileExistsError(path)
        os.fchmod(descriptor, 0o700)
        return descriptor
    except FileExistsError:
        os.close(descriptor)
        raise
    except OSError as exc:
        os.close(descriptor)
        raise ToolError(f"Refusing symlinked {label} or unsafe directory") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _private_parent_descriptor(path: Path, *, label: str) -> tuple[int, str]:
    name = path.name
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ToolError(f"Invalid {label} filename")
    ensure_owner_only_directory(path.parent, parents=True, label=label)
    descriptor = _open_owner_only_directory(
        path.parent,
        parents=False,
        label=label,
    )
    return descriptor, name


def _private_file_information(descriptor: int, *, label: str) -> os.stat_result:
    information = os.fstat(descriptor)
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_uid != os.geteuid()
        or stat.S_IMODE(information.st_mode) & 0o077
    ):
        raise ToolError(f"{label.capitalize()} file is not an owned private regular file")
    return information


def reserve_private_json(path: Path, value: Any, *, label: str = "state") -> None:
    """Create one owner-only JSON file, failing if the name already exists."""

    parent, name = _private_parent_descriptor(path, label=label)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(f"{json.dumps(value, sort_keys=True)}\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


def atomic_write_private_json(path: Path, value: Any, *, label: str = "state") -> None:
    """Atomically replace an owner-only JSON file without following symlinks."""

    parent, name = _private_parent_descriptor(path, label=label)
    temporary_name = f".{name}.{secrets.token_hex(12)}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        try:
            existing = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
        except FileNotFoundError:
            existing = None
        except OSError as exc:
            raise ToolError(f"{label.capitalize()} file is symlinked or unsafe") from exc
        if existing is not None:
            try:
                _private_file_information(existing, label=label)
            finally:
                os.close(existing)
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(f"{json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False)}\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(
                temporary_name,
                name,
                src_dir_fd=parent,
                dst_dir_fd=parent,
            )
            os.fsync(parent)
        except BaseException:
            try:
                os.unlink(temporary_name, dir_fd=parent)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(parent)


def read_private_json(
    path: Path,
    *,
    max_bytes: int = 256_000,
    label: str = "state",
) -> Any:
    """Read one bounded owner-only JSON file without following symlinks."""

    parent, name = _private_parent_descriptor(path, label=label)
    descriptor: int | None = None
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent,
        )
        information = _private_file_information(descriptor, label=label)
        if information.st_size > max_bytes:
            raise ToolError(f"{label.capitalize()} file exceeds the {max_bytes}-byte limit")
        payload = bytearray()
        while len(payload) <= max_bytes:
            chunk = os.read(descriptor, min(65_536, max_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > max_bytes:
            raise ToolError(f"{label.capitalize()} file grew beyond the {max_bytes}-byte limit")
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ToolError(f"{label.capitalize()} file is not valid JSON") from exc
    except OSError as exc:
        raise ToolError(f"{label.capitalize()} file is symlinked or unsafe") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def snapshot_regular_file(
    source: Path,
    private_directory: Path,
    *,
    max_bytes: int,
    label: str = "source",
) -> Path:
    """Copy one no-follow regular file into an owner-only immutable snapshot."""

    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if not _SUPPORTS_SAFE_OPEN:
        raise ToolError(f"This platform cannot safely snapshot the {label}")
    absolute = source.expanduser()
    if not absolute.is_absolute():
        absolute = Path.cwd() / absolute
    if len(absolute.parts) < 2:
        raise ToolError(f"Invalid {label} path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    source_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    source_parent = os.open(absolute.anchor, directory_flags)
    source_descriptor: int | None = None
    destination_parent: int | None = None
    destination_name = f".{label.replace(' ', '-')}.{secrets.token_hex(12)}.snapshot"
    try:
        for part in absolute.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=source_parent)
            os.close(source_parent)
            source_parent = child
        source_descriptor = os.open(
            absolute.name,
            source_flags,
            dir_fd=source_parent,
        )
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 1 or before.st_size > max_bytes:
            raise ToolError(f"{label.capitalize()} is not one bounded regular file")
        ensure_owner_only_directory(
            private_directory,
            parents=True,
            label=f"{label} snapshot",
        )
        destination_parent = _open_owner_only_directory(
            private_directory,
            parents=False,
            label=f"{label} snapshot",
        )
        destination_descriptor = os.open(
            destination_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=destination_parent,
        )
        copied = 0
        try:
            while True:
                chunk = os.read(source_descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied += len(chunk)
                if copied > max_bytes:
                    raise ToolError(f"{label.capitalize()} grew beyond the size limit")
                view = memoryview(chunk)
                while view:
                    written = os.write(destination_descriptor, view)
                    view = view[written:]
            os.fsync(destination_descriptor)
        except BaseException:
            os.close(destination_descriptor)
            os.unlink(destination_name, dir_fd=destination_parent)
            raise
        os.close(destination_descriptor)
        after = os.fstat(source_descriptor)
        if (
            copied != before.st_size
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
        ):
            os.unlink(destination_name, dir_fd=destination_parent)
            raise ToolError(f"{label.capitalize()} changed while it was being snapshotted")
        os.fsync(destination_parent)
        return private_directory / destination_name
    except OSError as exc:
        raise ToolError(f"Unable to safely snapshot {label}: {exc.strerror or exc}") from exc
    finally:
        if destination_parent is not None:
            os.close(destination_parent)
        if source_descriptor is not None:
            os.close(source_descriptor)
        os.close(source_parent)


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
