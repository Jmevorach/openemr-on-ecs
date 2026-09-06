#!/usr/bin/env python3
"""Run npm audit and fail closed on any reported vulnerability."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def validate_report(report: dict[str, Any]) -> list[str]:
    """Return reasons the audit report is not completely clean."""

    vulnerabilities = report.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        return ["npm audit report has no vulnerabilities object"]
    return [f"vulnerable package: {name}" for name in sorted(vulnerabilities)]


def main() -> int:
    """Run npm audit and fail when any vulnerability is reported."""

    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        ["npm", "audit", "--json"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        report = json.loads(result.stdout or "{}")
    except json.JSONDecodeError:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode or 1

    failures = validate_report(report)
    if failures:
        print("\n".join(f"- {failure}" for failure in failures), file=sys.stderr)
        return 1

    print("npm audit: no vulnerabilities")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
