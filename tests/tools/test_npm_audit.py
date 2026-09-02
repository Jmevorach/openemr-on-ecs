"""Tests for the fail-closed npm audit check."""

from __future__ import annotations

from scripts.check_npm_audit import validate_report


def test_clean_audit_passes() -> None:
    assert validate_report({"vulnerabilities": {}}) == []


def test_missing_vulnerabilities_object_fails_closed() -> None:
    assert validate_report({}) == ["npm audit report has no vulnerabilities object"]


def test_any_vulnerability_fails_closed() -> None:
    report = {
        "vulnerabilities": {
            "other-package": {"severity": "low", "isDirect": True},
            "brace-expansion": {"severity": "high", "isDirect": False},
        }
    }

    assert validate_report(report) == [
        "vulnerable package: brace-expansion",
        "vulnerable package: other-package",
    ]
