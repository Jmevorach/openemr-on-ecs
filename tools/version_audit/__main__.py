"""Command-line entry point for ``python -m tools.version_audit``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from tools._shared import ToolError, atomic_write_json, atomic_write_text, repository_root

from .audit import run_audit
from .inventory import collect_declarations
from .render import render_human, render_markdown

EXIT_OK = 0
EXIT_UPDATES = 1
EXIT_USAGE = 2
EXIT_AUDIT_ERROR = 3
EXIT_ALL_SOURCES_FAILED = 4


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.version_audit",
        description=(
            "Audit declared dependency, platform, container, toolchain, action, and "
            "pre-commit versions without modifying declarations."
        ),
    )
    parser.add_argument(
        "--category",
        action="append",
        default=[],
        help="Limit the audit to a category; repeat or use comma-separated values.",
    )
    parser.add_argument("--json", dest="json_path", type=Path, help="Write the structured JSON report to PATH.")
    parser.add_argument(
        "--markdown",
        dest="markdown_path",
        type=Path,
        help="Write the generated Markdown report to PATH.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=12.0,
        help="Per-request network timeout in seconds (default: 12).",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Inventory declarations without making network requests.",
    )
    parser.add_argument(
        "--fail-on-updates",
        action="store_true",
        help=f"Exit {EXIT_UPDATES} when actionable stable/manual-review findings exist.",
    )
    parser.add_argument(
        "--fail-if-all-sources-fail",
        action="store_true",
        help=f"Exit {EXIT_ALL_SOURCES_FAILED} if every selected source is unavailable.",
    )
    parser.add_argument(
        "--timestamp",
        help="Override the report timestamp (useful for reproducible generated artifacts).",
    )
    parser.add_argument(
        "--list-categories",
        action="store_true",
        help="List discoverable categories and exit.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Do not print the human-readable terminal report.",
    )
    return parser


def _categories(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(sorted({category.strip() for value in values for category in value.split(",") if category.strip()}))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line audit and return its documented exit code."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        root = repository_root()
        declarations = collect_declarations(root)
        available_categories = tuple(sorted({item.category for item in declarations}))
        if args.list_categories:
            print("\n".join(available_categories))
            return EXIT_OK
        selected_categories = _categories(args.category)
        unknown = sorted(set(selected_categories) - set(available_categories))
        if unknown:
            parser.error(f"unknown category: {', '.join(unknown)}; available: {', '.join(available_categories)}")
        if args.timeout <= 0:
            parser.error("--timeout must be positive")
        report = run_audit(
            root,
            categories=selected_categories,
            timeout_seconds=args.timeout,
            online=not args.offline,
            generated_at=args.timestamp,
        )
        if args.json_path:
            output = args.json_path if args.json_path.is_absolute() else root / args.json_path
            atomic_write_json(output, report.to_dict())
        if args.markdown_path:
            output = args.markdown_path if args.markdown_path.is_absolute() else root / args.markdown_path
            atomic_write_text(output, render_markdown(report))
        if not args.quiet:
            sys.stdout.write(render_human(report))
        if (
            args.fail_if_all_sources_fail
            and report.findings
            and all(finding.latest is None for finding in report.findings)
        ):
            return EXIT_ALL_SOURCES_FAILED
        if args.fail_on_updates and report.updates_found:
            return EXIT_UPDATES
        return EXIT_OK
    except (OSError, ToolError, ValueError, json.JSONDecodeError) as exc:
        print(f"version audit failed: {exc}", file=sys.stderr)
        return EXIT_AUDIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
