"""Repository declaration discovery for the local version audit."""

from __future__ import annotations

import ast
import json
import os
import re
from collections import defaultdict
from functools import lru_cache
from pathlib import Path
from typing import Callable, Iterable, Iterator

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from tools._shared import ToolError, is_secret_like_path, redact_text, resolve_repo_path

from .models import Declaration

_TEXT_SUFFIXES = {
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
_SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    "__pycache__",
    "cdk.out",
    "htmlcov",
    "node_modules",
    "tmp",
}


class InventorySource:
    """Optional closed set of repository files and its policy-enforcing reader."""

    def __init__(
        self,
        root: Path,
        *,
        paths: Iterable[str] | None = None,
        reader: Callable[[str], str] | None = None,
    ):
        self.root = root.resolve()
        if (paths is None) != (reader is None):
            raise ValueError("paths and reader must be provided together")
        selected: list[str] | None = None
        if paths is not None:
            selected = []
            for value in paths:
                relative = Path(value)
                if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                    raise ToolError("Inventory source paths must be repository-relative")
                selected.append(relative.as_posix())
        self._selected = tuple(sorted(set(selected))) if selected is not None else None
        self._selected_set = set(self._selected or ())
        self._reader = reader

    @property
    def restricted(self) -> bool:
        """Return whether enumeration is limited to an explicit path set."""

        return self._selected is not None

    def _relative(self, path: Path) -> str:
        candidate = path if path.is_absolute() else self.root / path
        try:
            relative = candidate.relative_to(self.root)
        except ValueError as exc:
            raise ToolError("Inventory path escapes the repository root") from exc
        if ".." in relative.parts or not relative.parts:
            raise ToolError("Inventory path escapes the repository root")
        return relative.as_posix()

    def contains(self, path: Path) -> bool:
        """Return whether a regular file is available to this inventory."""

        try:
            relative = self._relative(path)
        except ToolError:
            return False
        if self.restricted:
            return relative in self._selected_set
        candidate = self.root / relative
        return candidate.is_file() and not candidate.is_symlink()

    def resolve(self, path: Path, *, allowed_extensions: set[str] | None = None) -> Path:
        """Resolve an inventory path without widening a restricted source."""

        relative = self._relative(path)
        if self.restricted:
            if relative not in self._selected_set:
                raise ToolError("Inventory path is outside the approved input set")
            candidate = self.root / relative
            if allowed_extensions is not None and candidate.suffix.lower() not in allowed_extensions:
                raise ToolError("Inventory path has an unsupported extension")
            return candidate
        return resolve_repo_path(
            self.root,
            self.root / relative,
            allowed_extensions=allowed_extensions,
        )

    def read_text(self, path: Path) -> str:
        """Read a file through the configured policy."""

        relative = self._relative(path)
        if self.restricted:
            if relative not in self._selected_set or self._reader is None:
                raise ToolError("Inventory path is outside the approved input set")
            return self._reader(relative)
        return (self.root / relative).read_text(encoding="utf-8")

    def selected_paths(self) -> tuple[Path, ...]:
        """Return the closed path set; unrestricted callers receive no paths."""

        if self._selected is None:
            return ()
        return tuple(self.root / relative for relative in self._selected)


def _relative(root: Path, path: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _iter_text_files(root: Path) -> Iterator[Path]:
    paths: list[Path] = []
    root = root.resolve()
    for directory, child_directories, filenames in os.walk(root):
        base = Path(directory)
        child_directories[:] = sorted(
            name
            for name in child_directories
            if name not in _SKIP_DIRECTORIES
            and not is_secret_like_path((base / name).relative_to(root))
            and not (base / name).is_symlink()
        )
        for filename in filenames:
            path = base / filename
            relative = path.relative_to(root)
            if (
                not path.is_symlink()
                and not is_secret_like_path(relative)
                and (path.suffix.lower() in _TEXT_SUFFIXES or filename == "Dockerfile")
            ):
                paths.append(path)
    yield from sorted(paths)


@lru_cache(maxsize=8)
def _text_corpus(root_value: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    root = Path(root_value)
    corpus: list[tuple[str, tuple[str, ...]]] = []
    for path in _iter_text_files(root):
        try:
            lines = tuple(path.read_text(encoding="utf-8").splitlines())
        except UnicodeDecodeError:
            continue
        corpus.append((_relative(root, path), lines))
    return tuple(corpus)


def _line_location(root: Path, path: Path, line_number: int) -> str:
    return f"{_relative(root, path)}:{line_number}"


def _discover_value_consumers(root: Path, value: str, definitions: Iterable[str]) -> tuple[str, ...]:
    if not value or len(value) < 2:
        return ()
    definition_paths = {item.split(":", 1)[0] for item in definitions}
    consumers: list[str] = []
    for relative, lines in _text_corpus(str(root.resolve())):
        for line_number, line in enumerate(lines, start=1):
            if value not in line:
                continue
            location = f"{relative}:{line_number}"
            if relative not in definition_paths:
                consumers.append(location)
    return tuple(consumers[:25])


def _requirement_lines(
    root: Path,
    path: Path,
    seen: set[Path] | None = None,
    *,
    source: InventorySource | None = None,
) -> Iterator[tuple[Path, int, str]]:
    source = source or InventorySource(root)
    seen = seen or set()
    if not source.contains(path):
        return
    path = source.resolve(
        path,
        allowed_extensions={".in", ".txt"},
    )
    if path in seen:
        return
    seen.add(path)
    for line_number, raw_line in enumerate(source.read_text(path).splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        include = re.match(r"^(?:-r|--requirement|-c|--constraint)\s+(.+)$", stripped)
        if include:
            try:
                include_path = source.resolve(
                    path.parent / include.group(1).strip(),
                    allowed_extensions={".in", ".txt"},
                )
            except ToolError:
                yield path, line_number, raw_line
                continue
            yield from _requirement_lines(root, include_path, seen, source=source)
            continue
        yield path, line_number, raw_line


def collect_python_declarations(
    root: Path,
    *,
    discover_consumers: bool = True,
    source: InventorySource | None = None,
) -> list[Declaration]:
    """Read direct PEP 508 declarations without consulting installed packages."""

    source = source or InventorySource(root)
    requirement_files = [
        root / "requirements.txt",
        root / "requirements-dev.txt",
        root / "tools" / "credential-rotation" / "requirements.txt",
    ]
    grouped: dict[str, list[tuple[Path, int, Requirement, str]]] = defaultdict(list)
    malformed: list[Declaration] = []
    for requirement_file in requirement_files:
        category = "python-dev" if requirement_file.name == "requirements-dev.txt" else "python-production"
        for path, line_number, raw_line in _requirement_lines(
            root,
            requirement_file,
            source=source,
        ):
            line = raw_line.split(" #", 1)[0].strip()
            if line.startswith("-e "):
                line = line[3:].strip()
            if line.startswith(("--", "-f ", "--find-links ")):
                continue
            try:
                requirement = Requirement(line)
            except InvalidRequirement:
                malformed.append(
                    Declaration(
                        identifier=f"python-invalid:{_relative(root, path)}:{line_number}",
                        name=redact_text(line),
                        category=category,
                        current="invalid declaration",
                        definition=_line_location(root, path, line_number),
                        source_kind="inventory-error",
                        metadata={"error": "Invalid PEP 508 requirement"},
                    )
                )
                continue
            grouped[canonicalize_name(requirement.name)].append((path, line_number, requirement, category))

    declarations: list[Declaration] = []
    for normalized_name, entries in sorted(grouped.items()):
        definitions = tuple(_line_location(root, path, line) for path, line, _, _ in entries)
        requirements = [entry[2] for entry in entries]
        categories = {entry[3] for entry in entries}
        category = next(iter(categories)) if len(categories) == 1 else "python-shared"
        constraints = {str(requirement.specifier) for requirement in requirements}
        urls = {redact_text(requirement.url) for requirement in requirements if requirement.url}
        exact_versions = {
            specifier.version
            for requirement in requirements
            for specifier in requirement.specifier
            if specifier.operator in {"==", "==="} and "*" not in specifier.version
        }
        if len(exact_versions) == 1:
            current = next(iter(exact_versions))
        elif constraints != {""}:
            current = " / ".join(sorted(value or "<unbounded>" for value in constraints))
        elif urls:
            current = " / ".join(sorted(str(value) for value in urls))
        else:
            current = "unbounded"
        first = requirements[0]
        declarations.append(
            Declaration(
                identifier=f"python:{normalized_name}",
                name=first.name,
                category=category,
                current=current,
                definition=", ".join(definitions),
                source_kind="pypi" if not urls else "manual",
                consumers=(_discover_value_consumers(root, current, definitions) if discover_consumers else ()),
                constraint=" / ".join(sorted(constraints)),
                metadata={
                    "normalized_name": normalized_name,
                    "markers": sorted({str(req.marker) for req in requirements if req.marker}),
                    "extras": sorted({extra for req in requirements for extra in req.extras}),
                    "urls": sorted(str(url) for url in urls),
                    "conflicting_exact_pins": len(exact_versions) > 1,
                },
            )
        )
    return declarations + malformed


def _parse_go_requirements(content: str) -> list[tuple[int, str, str]]:
    declarations: list[tuple[int, str, str]] = []
    in_require_block = False
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()
        if stripped == "require (":
            in_require_block = True
            continue
        if in_require_block and stripped == ")":
            in_require_block = False
            continue
        candidate = stripped
        if candidate.startswith("require "):
            candidate = candidate.removeprefix("require ").strip()
        elif not in_require_block:
            continue
        if not candidate or candidate.startswith("//") or "// indirect" in candidate:
            continue
        parts = candidate.split()
        if len(parts) >= 2 and parts[1].startswith("v"):
            declarations.append((line_number, parts[0], parts[1]))
    return declarations


def collect_go_declarations(
    root: Path,
    *,
    discover_consumers: bool = True,
    source: InventorySource | None = None,
) -> list[Declaration]:
    """Collect direct Go dependencies and the declared Go language version."""

    source = source or InventorySource(root)
    go_mod = root / "scripts" / "backup-tui" / "go.mod"
    if not source.contains(go_mod):
        return []
    declarations: list[Declaration] = []
    content = source.read_text(go_mod)
    lines = content.splitlines()
    for line_number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"\s*go\s+(\d+(?:\.\d+){1,2})\s*", line)
        if match:
            value = match.group(1)
            definition = _line_location(root, go_mod, line_number)
            declarations.append(
                Declaration(
                    identifier="toolchain:go",
                    name="Go toolchain",
                    category="toolchains",
                    current=value,
                    definition=definition,
                    source_kind="go-toolchain",
                    consumers=(_discover_value_consumers(root, value, (definition,)) if discover_consumers else ()),
                )
            )
            break
    for line_number, module, version in _parse_go_requirements(content):
        definition = _line_location(root, go_mod, line_number)
        declarations.append(
            Declaration(
                identifier=f"go:{module}",
                name=module,
                category="go",
                current=version,
                definition=definition,
                source_kind="go-proxy",
                consumers=(_discover_value_consumers(root, version, (definition,)) if discover_consumers else ()),
                metadata={"module": module},
            )
        )
    return declarations


def _attribute_name(node: ast.AST) -> str | None:
    parts: list[str] = []
    current = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
        return ".".join(reversed(parts))
    return None


def collect_stack_platform_declarations(
    root: Path,
    *,
    discover_consumers: bool = True,
    source: InventorySource | None = None,
) -> list[Declaration]:
    """Collect platform versions from the central StackConstants class."""

    source = source or InventorySource(root)
    constants_path = root / "openemr_ecs" / "constants.py"
    if not source.contains(constants_path):
        return []
    tree = ast.parse(source.read_text(constants_path), filename=str(constants_path))
    assignments: dict[str, tuple[int, str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        value_node = node.value
        if value_node is None:
            continue
        value: str | None
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, (str, int, float)):
            value = str(value_node.value)
        else:
            value = _attribute_name(value_node)
        if value is None:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                assignments[target.id] = (node.lineno, value)

    specifications = {
        "AURORA_MYSQL_ENGINE_VERSION": (
            "platform:aurora-mysql",
            "Aurora MySQL engine",
            "aws-cdk-aurora",
        ),
        "CREDENTIAL_ROTATION_PYTHON_VERSION": (
            "toolchain:credential-python",
            "Credential rotation Python",
            "python-toolchain",
        ),
        "EMR_SERVERLESS_RELEASE_LABEL": (
            "platform:emr-serverless",
            "EMR Serverless release",
            "emr-serverless",
        ),
        "LAMBDA_PYTHON_RUNTIME": (
            "platform:lambda-python",
            "AWS Lambda Python runtime",
            "lambda-runtime",
        ),
        "OPENEMR_VERSION": (
            "container:openemr",
            "OpenEMR container",
            "openemr-container",
        ),
    }
    declarations: list[Declaration] = []
    for constant_name, (identifier, display_name, source_kind) in specifications.items():
        if constant_name not in assignments:
            continue
        line_number, raw_value = assignments[constant_name]
        if constant_name == "AURORA_MYSQL_ENGINE_VERSION":
            current = raw_value.rsplit(".", 1)[-1].removeprefix("VER_").replace("_", ".")
        elif constant_name == "LAMBDA_PYTHON_RUNTIME":
            current = raw_value.rsplit(".", 1)[-1].removeprefix("PYTHON_").replace("_", ".")
        else:
            current = raw_value
        definition = _line_location(root, constants_path, line_number)
        metadata = {"constant": constant_name, "raw_value": raw_value}
        explicit_consumers: tuple[str, ...] = ()
        if constant_name == "OPENEMR_VERSION":
            digest_assignment = assignments.get("OPENEMR_ARM64_DIGEST")
            if digest_assignment is None:
                metadata["arm64_digest"] = ""
            else:
                digest_line, digest = digest_assignment
                metadata["arm64_digest"] = digest
                explicit_consumers = (_line_location(root, constants_path, digest_line),)
        discovered_consumers = _discover_value_consumers(root, current, (definition,)) if discover_consumers else ()
        declarations.append(
            Declaration(
                identifier=identifier,
                name=display_name,
                category="containers" if identifier.startswith("container:") else "platforms",
                current=current,
                definition=definition,
                source_kind=source_kind,
                consumers=tuple(sorted(set((*discovered_consumers, *explicit_consumers)))),
                metadata=metadata,
            )
        )
    return declarations


def collect_action_declarations(
    root: Path,
    *,
    source: InventorySource | None = None,
) -> list[Declaration]:
    """Collect unique external GitHub Actions pins."""

    source = source or InventorySource(root)
    matches: dict[str, list[tuple[Path, int, str, str]]] = defaultdict(list)
    pattern = re.compile(r"^\s*(?:-\s*)?uses:\s*([^@\s#]+)@([^\s#]+)(?:\s+#\s*(\S+))?")
    workflows = (
        [
            path
            for path in source.selected_paths()
            if path.parent == source.root / ".github" / "workflows" and path.suffix == ".yml"
        ]
        if source.restricted
        else list((root / ".github" / "workflows").glob("*.yml"))
    )
    for workflow in sorted(workflows):
        if not source.contains(workflow):
            continue
        for line_number, line in enumerate(source.read_text(workflow).splitlines(), start=1):
            match = pattern.match(line)
            if not match or match.group(1).startswith(("./", "docker://")):
                continue
            action, revision, comment = match.groups()
            display_revision = (
                comment
                if re.fullmatch(r"[0-9a-fA-F]{40}", revision)
                and comment
                and re.fullmatch(r"v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?", comment)
                else revision
            )
            matches[action].append((workflow, line_number, revision, display_revision))
    declarations: list[Declaration] = []
    for action, entries in sorted(matches.items()):
        revisions = sorted({entry[2] for entry in entries})
        display_revisions = sorted({entry[3] for entry in entries})
        definitions = tuple(_line_location(root, path, line) for path, line, _, _ in entries)
        declarations.append(
            Declaration(
                identifier=f"github-action:{action.lower()}",
                name=action,
                category="github-actions",
                current=" / ".join(display_revisions),
                definition=", ".join(definitions),
                source_kind="github-release",
                consumers=definitions[1:],
                constraint="same major unless release notes approve a major upgrade",
                metadata={
                    "repository": action,
                    "conflicting_pins": len(revisions) > 1,
                    "revisions": revisions,
                    "revision_labels": {revision: display for _, _, revision, display in entries},
                    "immutable_sha_pins": all(re.fullmatch(r"[0-9a-fA-F]{40}", revision) for revision in revisions),
                },
            )
        )
    return declarations


def collect_precommit_declarations(
    root: Path,
    *,
    source: InventorySource | None = None,
) -> list[Declaration]:
    """Collect repository and revision pairs from pre-commit configuration."""

    source = source or InventorySource(root)
    config_path = root / ".pre-commit-config.yaml"
    if not source.contains(config_path):
        return []
    repository: str | None = None
    repository_line = 0
    declarations: list[Declaration] = []
    for line_number, line in enumerate(source.read_text(config_path).splitlines(), start=1):
        repo_match = re.match(r"\s*-\s+repo:\s*(\S+)", line)
        if repo_match:
            repository = repo_match.group(1)
            repository_line = line_number
            continue
        revision_match = re.match(r"\s+rev:\s*(\S+)(?:\s+#\s*(\S+))?", line)
        if revision_match and repository and repository != "local":
            revision = revision_match.group(1)
            label = revision_match.group(2)
            display_revision = (
                label
                if re.fullmatch(r"[0-9a-fA-F]{40}", revision)
                and label
                and re.fullmatch(r"v?\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.-]+)?", label)
                else revision
            )
            repository_slug = repository.removesuffix(".git").split("github.com/", 1)[-1]
            definitions = (
                _line_location(root, config_path, repository_line),
                _line_location(root, config_path, line_number),
            )
            declarations.append(
                Declaration(
                    identifier=f"precommit:{repository_slug.lower()}",
                    name=repository_slug,
                    category="pre-commit",
                    current=display_revision,
                    definition=", ".join(definitions),
                    source_kind="github-release",
                    metadata={
                        "repository": repository_slug,
                        "revisions": [revision],
                        "revision_labels": {revision: display_revision},
                        "immutable_sha_pins": bool(re.fullmatch(r"[0-9a-fA-F]{40}", revision)),
                    },
                )
            )
    return declarations


def collect_node_declarations(
    root: Path,
    *,
    discover_consumers: bool = True,
    source: InventorySource | None = None,
) -> list[Declaration]:
    """Collect resolved Node.js dependencies from the committed npm manifest."""

    source = source or InventorySource(root)
    package_path = root / "package.json"
    if not source.contains(package_path):
        return []
    package_content = source.read_text(package_path)
    package = json.loads(package_content)
    lock_path = root / "package-lock.json"
    lock = json.loads(source.read_text(lock_path)) if source.contains(lock_path) else {}
    locked_packages = lock.get("packages", {}) if isinstance(lock, dict) else {}
    if not isinstance(locked_packages, dict):
        locked_packages = {}

    dependencies: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        values = package.get(section, {})
        if not isinstance(values, dict):
            continue
        for name, constraint in values.items():
            if isinstance(name, str) and isinstance(constraint, str):
                dependencies[name] = constraint

    lines = package_content.splitlines()
    declarations: list[Declaration] = []
    for name, constraint in sorted(dependencies.items()):
        locked = locked_packages.get(f"node_modules/{name}", {})
        current = str(locked.get("version", "")).strip() if isinstance(locked, dict) else ""
        if not current:
            current = constraint.lstrip("=v~^")
        line_number = next(
            (number for number, line in enumerate(lines, start=1) if re.search(rf'"{re.escape(name)}"\s*:', line)),
            1,
        )
        definition = _line_location(root, package_path, line_number)
        declarations.append(
            Declaration(
                identifier=f"node:{name.lower()}",
                name=name,
                category="node",
                current=current,
                definition=definition,
                source_kind="npm",
                constraint=constraint,
                consumers=(_discover_value_consumers(root, current, (definition,)) if discover_consumers else ()),
                metadata={"package": name},
            )
        )
    return declarations


def collect_workflow_toolchains(
    root: Path,
    *,
    source: InventorySource | None = None,
) -> list[Declaration]:
    """Collect shared toolchain versions from workflows and runtime manifests."""

    source = source or InventorySource(root)
    declarations: dict[str, list[tuple[Path, int, str, str]]] = defaultdict(list)
    patterns = [
        (
            "toolchain:python",
            "Python toolchain",
            "python-toolchain",
            re.compile(r"PYTHON_VERSION:\s*[\"']?([^\"'\s#]+)"),
        ),
        ("toolchain:pip", "pip", "pypi", re.compile(r"PIP_VERSION:\s*[\"']?([^\"'\s#]+)")),
        ("toolchain:semver", "semver", "pypi", re.compile(r"SEMVER_VERSION:\s*[\"']?([^\"'\s#]+)")),
        (
            "toolchain:shellcheck",
            "ShellCheck",
            "github-release",
            re.compile(r"SHELLCHECK_VERSION:\s*[\"']?([^\"'\s#]+)"),
        ),
        ("toolchain:node", "Node.js toolchain", "node-toolchain", re.compile(r"NODE_VERSION:\s*[\"']?([^\"'\s#]+)")),
        (
            "toolchain:go-workflow",
            "Go workflow toolchain",
            "go-toolchain",
            re.compile(r"go-version:\s*[\"']?([^\"'\s#]+)"),
        ),
        ("toolchain:cdk-cli", "AWS CDK CLI", "npm", re.compile(r"\baws-cdk@([^\s\"']+)")),
        (
            "toolchain:golangci-lint",
            "golangci-lint",
            "github-release",
            re.compile(r"golangci-lint(?:/v2)?/cmd/golangci-lint@([^\s\"']+)"),
        ),
    ]
    workflows = (
        [
            path
            for path in source.selected_paths()
            if path.parent == source.root / ".github" / "workflows" and path.suffix == ".yml"
        ]
        if source.restricted
        else list((root / ".github" / "workflows").glob("*.yml"))
    )
    for workflow in sorted(workflows):
        if not source.contains(workflow):
            continue
        for line_number, line in enumerate(source.read_text(workflow).splitlines(), start=1):
            for identifier, name, source_kind, pattern in patterns:
                match = pattern.search(line)
                if match:
                    declarations[identifier].append((workflow, line_number, match.group(1), name + "|" + source_kind))
    package_path = root / "package.json"
    if source.contains(package_path):
        package_lines = source.read_text(package_path).splitlines()
        package = json.loads("\n".join(package_lines))
        engines = package.get("engines", {}) if isinstance(package, dict) else {}
        node_constraint = engines.get("node") if isinstance(engines, dict) else None
        node_major = re.search(r"(?<!\d)(\d+)", node_constraint) if isinstance(node_constraint, str) else None
        if node_major:
            line_number = next(
                (number for number, line in enumerate(package_lines, start=1) if re.search(r'"node"\s*:', line)),
                1,
            )
            declarations["toolchain:node"].append(
                (package_path, line_number, node_major.group(1), "Node.js toolchain|node-toolchain")
            )
    if source.restricted:
        dockerfiles = [path for path in source.selected_paths() if path.name == "Dockerfile"]
    else:
        dockerfiles = []
        for directory, child_directories, filenames in os.walk(root):
            child_directories[:] = sorted(name for name in child_directories if name not in _SKIP_DIRECTORIES)
            if "Dockerfile" in filenames:
                dockerfiles.append(Path(directory) / "Dockerfile")
    for dockerfile in sorted(dockerfiles):
        if not source.contains(dockerfile):
            continue
        for line_number, line in enumerate(source.read_text(dockerfile).splitlines(), start=1):
            match = re.match(r"\s*ARG\s+PYTHON_VERSION=([^\s#]+)", line)
            if match:
                declarations["toolchain:python"].append(
                    (dockerfile, line_number, match.group(1), "Python toolchain|python-toolchain")
                )
    result: list[Declaration] = []
    for identifier, entries in sorted(declarations.items()):
        versions = sorted({entry[2] for entry in entries})
        name, source_kind = entries[0][3].split("|", 1)
        definitions = tuple(_line_location(root, path, line) for path, line, _, _ in entries)
        metadata: dict[str, object] = {"conflicting_pins": len(versions) > 1}
        if identifier == "toolchain:golangci-lint":
            metadata["repository"] = "golangci/golangci-lint"
        if identifier == "toolchain:shellcheck":
            metadata["repository"] = "koalaman/shellcheck"
        if identifier == "toolchain:cdk-cli":
            metadata["package"] = "aws-cdk"
        result.append(
            Declaration(
                identifier=identifier,
                name=name,
                category="toolchains",
                current=" / ".join(versions),
                definition=", ".join(definitions),
                source_kind=source_kind,
                consumers=definitions[1:],
                metadata=metadata,
            )
        )
    return result


def collect_declarations(
    root: Path,
    *,
    discover_consumers: bool = True,
    source: InventorySource | None = None,
) -> tuple[Declaration, ...]:
    """Return the full normalized, deduplicated declaration inventory."""

    source = source or InventorySource(root)
    if root.resolve() != source.root:
        raise ValueError("Inventory source root does not match the collection root")
    if source.restricted and discover_consumers:
        raise ValueError("Restricted inventory sources cannot perform unrestricted consumer discovery")
    declarations = [
        *collect_python_declarations(
            root,
            discover_consumers=discover_consumers,
            source=source,
        ),
        *collect_go_declarations(
            root,
            discover_consumers=discover_consumers,
            source=source,
        ),
        *collect_stack_platform_declarations(
            root,
            discover_consumers=discover_consumers,
            source=source,
        ),
        *collect_action_declarations(root, source=source),
        *collect_precommit_declarations(root, source=source),
        *collect_node_declarations(
            root,
            discover_consumers=discover_consumers,
            source=source,
        ),
        *collect_workflow_toolchains(root, source=source),
    ]
    seen: set[str] = set()
    unique: list[Declaration] = []
    for declaration in sorted(declarations, key=lambda item: (item.category, item.identifier)):
        if declaration.identifier in seen:
            continue
        seen.add(declaration.identifier)
        unique.append(declaration)
    return tuple(unique)
