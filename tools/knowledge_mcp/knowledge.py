"""Bounded, offline repository knowledge used by the local MCP server."""

from __future__ import annotations

import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from tools._shared import (
    ToolError,
    is_secret_like_path,
    redact_text,
    repository_root,
    safe_read_text,
)
from tools.version_audit.inventory import collect_declarations

MAX_QUERY_LENGTH = 120
MAX_QUERY_TERMS = 8
MAX_RESULTS = 20
MAX_READ_LINES = 200
MAX_SEARCH_FILE_BYTES = 256_000

_ALLOWED_EXTENSIONS = {
    ".go",
    ".json",
    ".md",
    ".mod",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
_TOP_LEVEL_FILES = {
    ".flake8",
    ".gitignore",
    ".pre-commit-config.yaml",
    "ARCHITECTURE.md",
    "BACKUP-RESTORE-GUIDE.md",
    "CONTRIBUTING.md",
    "DETAILS.md",
    "GETTING-STARTED.md",
    "IMPORTING-OPENEMR.md",
    "KNOWLEDGE-MCP.md",
    "LIVE-E2E.md",
    "MAINTAINERS.md",
    "README-TESTING.md",
    "README.md",
    "TROUBLESHOOTING.md",
    "VERSION",
    "app.py",
    "cdk.json",
    "pyproject.toml",
    "package-lock.json",
    "package.json",
    "requirements-dev.txt",
    "requirements.txt",
}
_ALLOWED_PREFIXES = {
    ".github/workflows",
    "compose",
    "docs",
    "lambda",
    "openemr_ecs",
    "scripts",
    "tools",
}
_SENSITIVE_KEY = re.compile(
    r"(?:password|passwd|secret|token|access[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)

_TOPICS: dict[str, dict[str, Any]] = {
    "project-purpose": {
        "summary": "Deploy a secure, resilient OpenEMR environment on AWS ECS Fargate with CDK.",
        "sources": ["README.md", "GETTING-STARTED.md"],
    },
    "architecture": {
        "summary": "The stack combines edge routing, private ECS tasks, Aurora, Valkey, EFS, and AWS Backup.",
        "sources": ["ARCHITECTURE.md", "openemr_ecs/stack.py"],
    },
    "cdk": {
        "summary": "app.py creates OpenemrEcsStack; feature constructs live under openemr_ecs/.",
        "sources": ["app.py", "openemr_ecs/stack.py", "cdk.json"],
    },
    "ecs-fargate": {
        "summary": "OpenEMR runs as ARM64 Fargate tasks with shared EFS and guarded first-boot coordination.",
        "sources": ["ARCHITECTURE.md", "openemr_ecs/compute.py"],
    },
    "networking": {
        "summary": "Public edge resources route to tasks in private subnets with explicit security-group paths.",
        "sources": ["ARCHITECTURE.md", "openemr_ecs/network.py"],
    },
    "alb": {
        "summary": "An Application Load Balancer performs public TLS termination and HTTPS target checks.",
        "sources": ["ARCHITECTURE.md", "openemr_ecs/compute.py"],
    },
    "waf": {
        "summary": "Optional WAF protections are attached at the application edge.",
        "sources": ["DETAILS.md", "openemr_ecs/security.py"],
    },
    "tls": {
        "summary": "The deployment requires Route 53-managed ACM or an explicit certificate ARN.",
        "sources": ["GETTING-STARTED.md", "openemr_ecs/security.py"],
    },
    "route53": {
        "summary": "Route 53 can provide DNS validation and application records for an owned hosted zone.",
        "sources": ["GETTING-STARTED.md", "openemr_ecs/security.py"],
    },
    "global-accelerator": {
        "summary": "Global Accelerator is an optional edge path and has separate cost implications.",
        "sources": ["DETAILS.md", "openemr_ecs/network.py"],
    },
    "aurora": {
        "summary": "Aurora MySQL Serverless v2 stores application data with encrypted connections and backups.",
        "sources": ["ARCHITECTURE.md", "openemr_ecs/database.py"],
    },
    "elasticache": {
        "summary": "A TLS-enabled ElastiCache Serverless Valkey cache supports OpenEMR caching.",
        "sources": ["ARCHITECTURE.md", "openemr_ecs/database.py"],
    },
    "efs": {
        "summary": "Encrypted EFS file systems persist OpenEMR sites data and shared TLS material.",
        "sources": ["ARCHITECTURE.md", "openemr_ecs/storage.py"],
    },
    "backup": {
        "summary": "AWS Backup protects Aurora and EFS; local scripts expose explicit backup operations.",
        "sources": ["BACKUP-RESTORE-GUIDE.md", "scripts/create-backup.sh"],
    },
    "credential-rotation": {
        "summary": "A dedicated one-off ECS task rotates credentials and updates persisted OpenEMR settings.",
        "sources": ["DETAILS.md", "scripts/run-credential-rotation.sh"],
    },
    "monitoring": {
        "summary": "Optional alarms, dashboards, logs, and notifications provide operational visibility.",
        "sources": ["DETAILS.md", "openemr_ecs/monitoring.py"],
    },
    "analytics": {
        "summary": "Optional analytics export and EMR Serverless resources are isolated behind context flags.",
        "sources": ["DETAILS.md", "openemr_ecs/analytics.py"],
    },
    "lambda": {
        "summary": "Lambda-backed custom resources support setup, cleanup, exports, and operational automation.",
        "sources": ["lambda/README.md", "openemr_ecs/cleanup.py"],
    },
    "configuration": {
        "summary": "CDK context controls optional features, capacities, certificates, retention, and operations.",
        "sources": ["DETAILS.md", "cdk.json"],
    },
    "versions": {
        "summary": "The local version audit inventories declared dependencies and authoritative stable releases.",
        "sources": ["MAINTAINERS.md", "tools/version_audit/__main__.py"],
    },
    "ci": {
        "summary": "GitHub Actions runs tests, synthesis, security checks, and static validation without live deployment.",
        "sources": [".github/workflows/ci.yml", "CONTRIBUTING.md"],
    },
    "local-testing": {
        "summary": "Unit, synthesis, Go, and Docker Compose checks are available without mutating AWS.",
        "sources": ["README-TESTING.md", "MAINTAINERS.md"],
    },
    "live-e2e": {
        "summary": "Live deployment testing is local-only and requires explicit account, region, and cost safeguards.",
        "sources": ["LIVE-E2E.md", "tools/live_e2e/__main__.py"],
    },
    "timing-reports": {
        "summary": "Approved live E2E runs append redacted phase timings and regenerate a deterministic report.",
        "sources": ["docs/deployment-timing.md", "tools/live_e2e/report.py"],
    },
    "imports": {
        "summary": "Import inspection and planning are offline; execution is fresh-target-only and explicitly guarded.",
        "sources": ["IMPORTING-OPENEMR.md", "docs/adr/0001-guarded-openemr-import.md"],
    },
    "cleanup": {
        "summary": "Cleanup is high risk and must target only named stack or run-owned resources.",
        "sources": ["TROUBLESHOOTING.md", "scripts/cleanup-all-stacks.sh"],
    },
    "restore": {
        "summary": "Restore procedures use AWS Backup recovery points and require post-restore validation.",
        "sources": ["BACKUP-RESTORE-GUIDE.md", "scripts/restore-from-backup.sh"],
    },
    "troubleshooting": {
        "summary": "The troubleshooting guide covers deployment, health, database, DNS, and cleanup diagnostics.",
        "sources": ["TROUBLESHOOTING.md"],
    },
    "costs": {
        "summary": "Costs depend on always-on database, cache, NAT, edge, backup, and optional analytics choices.",
        "sources": ["README.md", "DETAILS.md"],
    },
    "destructive-commands": {
        "summary": "Deploy, destroy, restore, cleanup, import execution, and live E2E require explicit human review.",
        "sources": ["MAINTAINERS.md", "LIVE-E2E.md", "IMPORTING-OPENEMR.md"],
    },
    "maintainer-workflows": {
        "summary": "The maintainer guide centralizes audit, test, import, MCP, E2E, and report commands.",
        "sources": ["MAINTAINERS.md"],
    },
    "knowledge-mcp": {
        "summary": "The local read-only MCP exposes bounded, redacted repository knowledge over STDIO.",
        "sources": ["KNOWLEDGE-MCP.md", "tools/knowledge_mcp/server.py"],
    },
}


class KnowledgeError(ValueError):
    """Raised for a bounded knowledge request that violates server policy."""


def _normalize_topic(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


class RepositoryKnowledge:
    """Read-only repository index with deterministic safety limits."""

    def __init__(self, root: Path | None = None):
        self.root = (root or repository_root()).resolve()

    def _is_allowed_relative(self, relative: Path) -> bool:
        if relative.is_absolute() or ".." in relative.parts or is_secret_like_path(relative):
            return False
        normalized = relative.as_posix()
        if normalized in _TOP_LEVEL_FILES:
            return True
        if relative.suffix.lower() not in _ALLOWED_EXTENSIONS:
            return False
        return any(normalized == prefix or normalized.startswith(f"{prefix}/") for prefix in _ALLOWED_PREFIXES)

    def _safe_files(self) -> list[Path]:
        files: list[Path] = []
        for current, directories, names in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            directories[:] = [
                directory
                for directory in directories
                if not is_secret_like_path((current_path / directory).relative_to(self.root))
            ]
            for name in names:
                path = current_path / name
                relative = path.relative_to(self.root)
                if not self._is_allowed_relative(relative) or path.is_symlink():
                    continue
                try:
                    if path.stat().st_size <= MAX_SEARCH_FILE_BYTES:
                        files.append(path)
                except OSError:
                    continue
        return sorted(files, key=lambda item: _relative(self.root, item))

    def _read(self, requested: str, *, max_bytes: int = MAX_SEARCH_FILE_BYTES) -> str:
        requested_path = Path(requested)
        if requested_path.is_absolute():
            raise KnowledgeError("Only repository-relative paths are accepted")
        if not self._is_allowed_relative(requested_path):
            raise KnowledgeError("Path is outside the MCP read policy")
        try:
            return redact_text(
                safe_read_text(
                    self.root,
                    requested_path,
                    max_bytes=max_bytes,
                    allowed_extensions=_ALLOWED_EXTENSIONS | {""},
                )
            )
        except ToolError as exc:
            raise KnowledgeError(str(exc)) from exc

    def overview(self) -> dict[str, Any]:
        """Return compact, non-sensitive project identity and entry points."""

        version = self._read("VERSION", max_bytes=128).strip()
        return {
            "name": "OpenEMR on ECS",
            "version": version,
            "purpose": _TOPICS["project-purpose"]["summary"],
            "cdk_entry_point": "app.py",
            "stack": "openemr_ecs.stack.OpenemrEcsStack",
            "configuration": "cdk.json context",
            "primary_guides": [
                "README.md",
                "GETTING-STARTED.md",
                "ARCHITECTURE.md",
                "DETAILS.md",
                "TROUBLESHOOTING.md",
                "KNOWLEDGE-MCP.md",
                "MAINTAINERS.md",
            ],
            "safety": "This server is offline and read-only; it cannot execute operational commands.",
        }

    def architecture(self) -> dict[str, Any]:
        """Return the high-level component map and source locations."""

        return {
            "request_path": [
                "Client",
                "Route 53 / optional Global Accelerator",
                "AWS WAF",
                "Application Load Balancer",
                "ECS Fargate OpenEMR service",
            ],
            "data_services": {
                "database": "Aurora MySQL Serverless v2",
                "cache": "ElastiCache Valkey",
                "shared_files": "Amazon EFS",
                "recovery": "AWS Backup",
            },
            "construct_sources": {
                "orchestration": "openemr_ecs/stack.py",
                "network": "openemr_ecs/network.py",
                "compute": "openemr_ecs/compute.py",
                "database": "openemr_ecs/database.py",
                "storage": "openemr_ecs/storage.py",
                "security": "openemr_ecs/security.py",
                "monitoring": "openemr_ecs/monitoring.py",
                "analytics": "openemr_ecs/analytics.py",
            },
            "details": "ARCHITECTURE.md",
        }

    def topic(self, topic: str) -> dict[str, Any]:
        """Return a curated topic summary and available local sources."""

        normalized = _normalize_topic(topic)
        aliases = {
            "ecs": "ecs-fargate",
            "fargate": "ecs-fargate",
            "cache": "elasticache",
            "valkey": "elasticache",
            "database": "aurora",
            "import": "imports",
            "mcp": "knowledge-mcp",
            "e2e": "live-e2e",
            "timings": "timing-reports",
            "route-53": "route53",
        }
        normalized = aliases.get(normalized, normalized)
        entry = _TOPICS.get(normalized)
        if entry is None:
            raise KnowledgeError(f"Unknown topic. Choose one of: {', '.join(sorted(_TOPICS))}")
        sources = [source for source in entry["sources"] if (self.root / source).is_file()]
        return {
            "topic": normalized,
            "summary": entry["summary"],
            "sources": sources,
            "search_terms": normalized.replace("-", " ").split(),
        }

    def search(self, query: str, *, limit: int = 8) -> list[dict[str, Any]]:
        """Search policy-approved repository text with a small relevance ranking."""

        query = query.strip()
        if len(query) < 2 or len(query) > MAX_QUERY_LENGTH:
            raise KnowledgeError(f"Query length must be between 2 and {MAX_QUERY_LENGTH} characters")
        if limit < 1 or limit > MAX_RESULTS:
            raise KnowledgeError(f"Result limit must be between 1 and {MAX_RESULTS}")
        terms = tuple(dict.fromkeys(re.findall(r"[a-z0-9][a-z0-9_-]*", query.lower())))
        if not terms or len(terms) > MAX_QUERY_TERMS:
            raise KnowledgeError(f"Query must contain 1 to {MAX_QUERY_TERMS} search terms")

        ranked: list[tuple[int, str, int, str]] = []
        phrase = query.lower()
        for path in self._safe_files():
            relative = _relative(self.root, path)
            try:
                text = self._read(relative)
            except KnowledgeError:
                continue
            path_lower = relative.lower()
            for line_number, line in enumerate(text.splitlines(), start=1):
                lowered = line.lower()
                matched = sum(term in lowered for term in terms)
                if matched == 0 and not any(term in path_lower for term in terms):
                    continue
                score = matched * 3
                if phrase in lowered:
                    score += 8
                if line.lstrip().startswith("#"):
                    score += 3
                score += sum(term in path_lower for term in terms)
                excerpt = re.sub(r"\s+", " ", line).strip()[:280]
                if excerpt:
                    ranked.append((score, relative, line_number, excerpt))

        ranked.sort(key=lambda item: (-item[0], item[1], item[2]))
        per_file: defaultdict[str, int] = defaultdict(int)
        results: list[dict[str, Any]] = []
        for score, relative, line_number, excerpt in ranked:
            if per_file[relative] >= 3:
                continue
            per_file[relative] += 1
            results.append(
                {
                    "path": relative,
                    "line": line_number,
                    "score": score,
                    "excerpt": excerpt,
                }
            )
            if len(results) == limit:
                break
        return results

    def read_file(
        self,
        path: str,
        *,
        start_line: int = 1,
        max_lines: int = 100,
    ) -> dict[str, Any]:
        """Read a bounded line range from an approved repository text file."""

        if start_line < 1:
            raise KnowledgeError("start_line must be at least 1")
        if max_lines < 1 or max_lines > MAX_READ_LINES:
            raise KnowledgeError(f"max_lines must be between 1 and {MAX_READ_LINES}")
        text = self._read(path)
        lines = text.splitlines()
        start_index = start_line - 1
        selected = lines[start_index : start_index + max_lines]
        return {
            "path": Path(path).as_posix(),
            "start_line": start_line,
            "end_line": start_line + len(selected) - 1 if selected else start_line - 1,
            "total_lines": len(lines),
            "content": "\n".join(selected),
            "truncated": start_index + len(selected) < len(lines),
        }

    def versions(self, categories: list[str] | None = None) -> dict[str, Any]:
        """Return declared versions without performing source or network lookups."""

        selected = {item.strip() for item in categories or [] if item.strip()}
        if len(selected) > 20:
            raise KnowledgeError("At most 20 categories may be requested")
        declarations = [
            declaration
            for declaration in collect_declarations(
                self.root,
                discover_consumers=False,
            )
            if not selected or declaration.category in selected
        ]
        return {
            "online_lookup": False,
            "count": len(declarations),
            "categories": sorted({item.category for item in declarations}),
            "components": [
                {
                    "identifier": item.identifier,
                    "name": item.name,
                    "category": item.category,
                    "declared": redact_text(item.current),
                    "definition": item.definition,
                    "constraint": redact_text(item.constraint or ""),
                }
                for item in declarations
            ],
        }

    def configuration(self) -> dict[str, Any]:
        """Return CDK context keys and redacted defaults."""

        try:
            data = json.loads(self._read("cdk.json"))
        except json.JSONDecodeError as exc:
            raise KnowledgeError("cdk.json is not valid JSON") from exc
        context = data.get("context", {})
        if not isinstance(context, dict):
            raise KnowledgeError("cdk.json context must be an object")
        entries = []
        for key, value in sorted(context.items()):
            rendered = "<redacted>" if _SENSITIVE_KEY.search(key) else redact_text(json.dumps(value, sort_keys=True))
            entries.append(
                {
                    "key": key,
                    "default": rendered,
                    "type": type(value).__name__,
                }
            )
        return {
            "source": "cdk.json",
            "count": len(entries),
            "entries": entries,
            "reference": "DETAILS.md",
        }

    def operational_commands(self) -> list[dict[str, Any]]:
        """Return discovery metadata; this method never executes a command."""

        return [
            {
                "purpose": "Version audit",
                "command": "python -m tools.version_audit --json report.json --markdown report.md",
                "risk": "read-only network lookup",
            },
            {
                "purpose": "Inspect import source",
                "command": "python -m tools.openemr_import inspect PATH --output inspection.json",
                "risk": "read-only local inspection",
            },
            {
                "purpose": "Plan import",
                "command": "python -m tools.openemr_import plan inspection.json --output plan.json",
                "risk": "writes only the requested local plan",
            },
            {
                "purpose": "Live E2E preflight",
                "command": (
                    "python -m tools.live_e2e preflight --approved-account ACCOUNT "
                    "--region REGION --route53-domain E2E_ZONE --allowed-ipv4-cidr IP/32 "
                    '--confirm-dedicated-zone "DEDICATED E2E ZONE" '
                    '--confirm-non-production-account "NON-PRODUCTION ACCOUNT"'
                ),
                "risk": "read-only AWS checks",
            },
            {
                "purpose": "Live E2E run",
                "command": (
                    "OPENEMR_LIVE_E2E_APPROVED_RUN_ID=RUN_ID "
                    "python -m tools.live_e2e run --preflight PREFLIGHT.json "
                    "--approved-account ACCOUNT "
                    '--confirm-create "CREATE LIVE E2E" '
                    '--confirm-destroy "DESTROY LIVE E2E" --confirm-costs'
                ),
                "risk": "creates billable AWS resources; local approval required",
            },
            {
                "purpose": "Backup",
                "command": "scripts/create-backup.sh",
                "risk": "creates AWS Backup recovery points and costs",
            },
            {
                "purpose": "Restore",
                "command": "scripts/restore-from-backup.sh",
                "risk": "destructive/high-risk recovery operation",
            },
            {
                "purpose": "Stack cleanup",
                "command": "scripts/cleanup-all-stacks.sh",
                "risk": "destructive; review target resources before use",
            },
        ]
