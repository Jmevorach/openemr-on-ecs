"""Typed records for guarded live deployment tests."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class PhaseTiming:
    """One measured phase with an explicit clock source."""

    name: str
    duration_seconds: float
    source: str
    started_at: str | None = None
    finished_at: str | None = None


@dataclass(frozen=True)
class CheckResult:
    """One preflight or deployment validation result."""

    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class ResidualResource:
    """A resource still visible after the stack deletion attempt."""

    resource_type: str
    identifier_hash: str
    disposition: str


@dataclass(frozen=True)
class RunResult:
    """Sanitized historical result safe to commit to the repository."""

    schema_version: int
    run_id: str
    started_at: str
    finished_at: str
    git_commit: str
    branch: str
    repository: str
    account_hash: str
    region: str
    safe_stack_id: str
    profile: str
    configuration_fingerprint: str
    bootstrap_state: str
    python_version: str
    node_version: str
    cdk_cli_version: str
    cdk_library_version: str
    openemr_version: str
    aurora_version: str
    test_runner_version: str
    status: str
    stack_status: str
    cleanup_status: str
    failure_phase: str | None
    import_duration_seconds: float | None
    phases: tuple[PhaseTiming, ...]
    checks: tuple[CheckResult, ...] = ()
    residuals: tuple[ResidualResource, ...] = ()
    notes: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        return asdict(self)
