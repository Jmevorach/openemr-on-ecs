"""Structured data model for version-audit results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Stable classifications used by all audit sources."""

    CURRENT = "current"
    STABLE_UPDATE = "stable_update_available"
    PRERELEASE_ONLY = "prerelease_only_update"
    UNABLE = "unable_to_determine"
    INCOMPATIBLE = "incompatible"
    DEFERRED = "deferred"
    MANUAL_REVIEW = "manual_review_required"


UPDATE_STATUSES = {
    Status.STABLE_UPDATE,
    Status.INCOMPATIBLE,
    Status.MANUAL_REVIEW,
}


@dataclass(frozen=True)
class Declaration:
    """A version declaration and its authoritative repository location."""

    identifier: str
    name: str
    category: str
    current: str
    definition: str
    source_kind: str
    consumers: tuple[str, ...] = ()
    constraint: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finding:
    """One normalized audit finding."""

    identifier: str
    name: str
    category: str
    current: str
    latest: str | None
    status: Status
    definition: str
    source_kind: str
    source_url: str | None
    consumers: tuple[str, ...] = ()
    constraint: str | None = None
    note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        value = asdict(self)
        value["status"] = self.status.value
        value["consumers"] = list(self.consumers)
        return value


@dataclass(frozen=True)
class AuditReport:
    """Complete normalized report returned by the audit."""

    generated_at: str
    repository_root: str
    findings: tuple[Finding, ...]
    selected_categories: tuple[str, ...]
    schema_version: int = 1

    @property
    def updates_found(self) -> bool:
        """Return whether actionable review or a stable update was found."""

        return any(finding.status in UPDATE_STATUSES for finding in self.findings)

    @property
    def partial_failure(self) -> bool:
        """Return whether at least one source could not be queried."""

        return any(finding.status is Status.UNABLE for finding in self.findings)

    def summary(self) -> dict[str, Any]:
        """Return deterministic counts by classification."""

        counts = {status.value: 0 for status in Status}
        for finding in self.findings:
            counts[finding.status.value] += 1
        return {
            "total": len(self.findings),
            "updates_found": self.updates_found,
            "partial_failure": self.partial_failure,
            "status_counts": counts,
        }

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation."""

        return {
            "schema_version": self.schema_version,
            "generated_at": self.generated_at,
            "repository_root": self.repository_root,
            "selected_categories": list(self.selected_categories),
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in self.findings],
        }
