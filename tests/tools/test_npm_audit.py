"""Tests for the narrowly scoped npm audit deferral."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from scripts.check_npm_audit import (
    ALLOWED_ADVISORY,
    ALLOWED_NODE,
    ALLOWED_URL,
    ALLOWED_VERSION,
    REVIEW_DATE,
    validate_report,
)


def _allowed_report() -> dict:
    return {
        "vulnerabilities": {
            "brace-expansion": {
                "severity": "high",
                "isDirect": False,
                "nodes": [ALLOWED_NODE],
                "via": [{"source": ALLOWED_ADVISORY, "url": ALLOWED_URL}],
            }
        }
    }


def _install_deferred_package(
    root: Path,
    *,
    version: str = ALLOWED_VERSION,
    locked_version: str | None = None,
) -> None:
    package = root / ALLOWED_NODE / "package.json"
    package.parent.mkdir(parents=True)
    package.write_text(json.dumps({"version": version}), encoding="utf-8")
    (root / "package-lock.json").write_text(
        json.dumps(
            {"packages": {ALLOWED_NODE: {"version": locked_version if locked_version is not None else version}}}
        ),
        encoding="utf-8",
    )


def test_clean_audit_passes_with_fixed_installed_version(tmp_path: Path) -> None:
    _install_deferred_package(tmp_path, version="5.0.9")

    assert validate_report({"vulnerabilities": {}}, tmp_path, today=date(2026, 8, 12)) == []


def test_exact_bundled_advisory_is_temporarily_deferred(tmp_path: Path) -> None:
    _install_deferred_package(tmp_path)

    assert validate_report(_allowed_report(), tmp_path, today=date(2026, 8, 12)) == []


def test_other_vulnerabilities_fail_closed(tmp_path: Path) -> None:
    report = _allowed_report()
    report["vulnerabilities"]["other-package"] = {
        "severity": "high",
        "isDirect": False,
        "nodes": ["node_modules/other-package"],
        "via": [],
    }
    _install_deferred_package(tmp_path)

    failures = validate_report(report, tmp_path, today=date(2026, 8, 12))

    assert failures == ["unexpected vulnerable package: other-package"]


def test_changed_path_or_version_fails_closed(tmp_path: Path) -> None:
    report = _allowed_report()
    report["vulnerabilities"]["brace-expansion"]["nodes"] = ["node_modules/brace-expansion"]
    _install_deferred_package(tmp_path, version="5.0.7")

    failures = validate_report(report, tmp_path, today=date(2026, 8, 12))

    assert "brace-expansion affected path changed" in failures
    assert any("unsupported installed version" in failure for failure in failures)


def test_clean_report_with_vulnerable_install_fails_closed(tmp_path: Path) -> None:
    _install_deferred_package(tmp_path)

    failures = validate_report(
        {"vulnerabilities": {}},
        tmp_path,
        today=date(2026, 8, 12),
    )

    assert failures == [f"brace-expansion {ALLOWED_VERSION} is installed but npm audit did not report {ALLOWED_URL}"]


def test_install_and_lock_mismatch_fails_closed(tmp_path: Path) -> None:
    _install_deferred_package(tmp_path, locked_version="5.0.9")

    failures = validate_report(_allowed_report(), tmp_path, today=date(2026, 8, 12))

    assert any("install/lock mismatch" in failure for failure in failures)


def test_deferral_expires_on_review_date(tmp_path: Path) -> None:
    _install_deferred_package(tmp_path)

    failures = validate_report(_allowed_report(), tmp_path, today=REVIEW_DATE)

    assert failures == [f"brace-expansion deferral expired on {REVIEW_DATE.isoformat()}"]
