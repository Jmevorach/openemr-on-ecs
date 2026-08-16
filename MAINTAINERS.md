# Maintainer Guide

This guide is the operational index for repository maintenance. Routine CI and
the commands in the first sections do not deploy infrastructure.

## Supported toolchains

- Python 3.14 for the application and all Python checks, including `cfn-lint`
- Node.js 24
- Go 1.26 for `scripts/backup-tui`
- AWS CDK v2 CLI
- Docker with Buildx for local container validation

Create a local environment:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install "pip==26.2.1"
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
npm ci
```

The private npm package contains pinned AWS CDK, `cdk-assets`, and cdk-dia CLIs
used by synthesis and diagram generation. Python production and development
requirements are exact pins; update them through the audited upgrade workflow
rather than relying on floating CI ranges.

## Command safety

- Tests, formatting checks, static analysis, offline version inventory,
  `scripts/stress-test.sh`, `scripts/test-cdk-synthesis.py`, and diagram
  synthesis are local-only. Diagram generation writes only its documented
  output artifacts.
- The online version audit performs public, read-only network requests.
- Deployment prerequisite checks read AWS configuration and resource state.
- Normal CDK deployment and operational scripts can change AWS resources. Use
  them only after reviewing their documented confirmation procedures.

## Read-only repository knowledge MCP

The optional local knowledge server gives MCP-capable assistants bounded,
redacted context about this repository. Start its STDIO entry point from the
repository root after installing the project dependencies:

```bash
.venv/bin/python -m tools.knowledge_mcp
```

Use [KNOWLEDGE-MCP.md](KNOWLEDGE-MCP.md) for client configuration, the complete
tool and resource inventory, output limits, examples, and troubleshooting.

The server is repository-root constrained and local-only. It has no write,
shell, subprocess, AWS, or network operations; rejects traversal, symlinks,
secret-like paths, unsupported or oversized files; redacts sensitive output;
and returns operational commands as documentation without executing them.

Run its focused checks before changing it:

```bash
.venv/bin/pytest tests/tools/test_knowledge_mcp.py -q
.venv/bin/black --check tools/_shared.py tools/knowledge_mcp tests/tools/test_knowledge_mcp.py
.venv/bin/flake8 tools/_shared.py tools/knowledge_mcp tests/tools/test_knowledge_mcp.py \
  --max-line-length=120 --extend-ignore=E203,W503,E501
.venv/bin/isort --check-only tools/_shared.py tools/knowledge_mcp tests/tools/test_knowledge_mcp.py
.venv/bin/mypy tools/_shared.py tools/knowledge_mcp
```

## Version audit

Inventory supported dependency, platform, container, action, and toolchain
declarations without network access:

```bash
.venv/bin/python -m tools.version_audit --offline
```

Resolve current stable versions from authoritative public sources and write
review artifacts:

```bash
.venv/bin/python -m tools.version_audit \
  --json /tmp/openemr-version-audit.json \
  --markdown /tmp/openemr-version-audit.md \
  --fail-if-all-sources-fail
```

List or select categories with `--list-categories` and repeated `--category`
arguments. Add `--fail-on-updates` in automation. Exit codes are `0` for a
completed audit, `1` for actionable findings when requested, `2` for CLI
usage, `3` for an audit error, and `4` when all selected online sources fail
and that condition was requested.

The audit never edits declarations. Review compatibility, release notes,
architecture support, and lockfile changes before upgrading. Record an
intentional temporary exception in `tools/version_audit/deferrals.json` with a
specific reason and review date; do not hide an update by weakening discovery.
The audit also verifies that labeled GitHub dependencies resolve to their
committed SHA pins.

The scheduled workflow in `.github/workflows/monthly-version-check.yml` runs
the same utility and opens or updates a GitHub issue when action is required.

## Local validation

Run the primary Python suite:

```bash
.venv/bin/pytest tests/ \
  --cov=openemr_ecs \
  --cov-report=term-missing \
  --cov-fail-under=90 \
  --maxfail=1 \
  -n auto \
  -m "not integration" \
  -q
```

Run formatting, linting, typing, and static security checks:

```bash
.venv/bin/black --check app.py openemr_ecs tests diagrams tools \
  scripts/check_npm_audit.py scripts/test-cdk-synthesis.py
.venv/bin/flake8 app.py openemr_ecs tests diagrams tools \
  scripts/check_npm_audit.py scripts/test-cdk-synthesis.py \
  --max-line-length=120 --extend-ignore=E203,W503,E501
.venv/bin/isort --check-only app.py openemr_ecs tests diagrams tools \
  scripts/check_npm_audit.py scripts/test-cdk-synthesis.py
.venv/bin/mypy app.py openemr_ecs diagrams tools/_shared.py \
  tools/version_audit tools/openemr_import \
  tools/openemr-import-worker/worker.py tools/credential-rotation/src \
  scripts/check_npm_audit.py scripts/test-cdk-synthesis.py
.venv/bin/bandit -r app.py openemr_ecs diagrams tools \
  scripts/check_npm_audit.py scripts/test-cdk-synthesis.py -ll
.venv/bin/pip-audit --strict --progress-spinner off \
  -r requirements.txt -r requirements-dev.txt \
  -r tools/credential-rotation/requirements.txt
.venv/bin/pip-audit --strict --progress-spinner off \
  -r tools/openemr-import-worker/requirements.txt
.venv/bin/python scripts/check_npm_audit.py
.venv/bin/pre-commit run
```

Run the final command after staging the intended changes; restage any safe
formatter updates before committing.

The npm check fails closed except for the exact bundled `brace-expansion`
advisory and package path recorded in `scripts/check_npm_audit.py`. That
temporary deferral expires on 2026-08-26. Remove it as soon as `aws-cdk-lib`
ships the corrected bundled dependency; do not update the lockfile version
without updating the installed package.

Validate the credential-rotation tool separately:

```bash
PYTHONPATH=tools/credential-rotation/src \
  .venv/bin/pytest tools/credential-rotation/tests -q
```

Validate Go code:

```bash
cd scripts/backup-tui
go mod verify
go test ./...
go vet ./...
test -z "$(gofmt -s -l .)"
```

Validate CDK synthesis without AWS lookups:

```bash
AWS_ACCESS_KEY_ID=fake \
AWS_SECRET_ACCESS_KEY=fake \
AWS_DEFAULT_REGION=us-west-2 \
CDK_DEFAULT_REGION=us-west-2 \
  node_modules/.bin/cdk synth --no-lookups \
  -c certificate_arn=arn:aws:acm:us-west-2:123456789012:certificate/00000000-0000-0000-0000-000000000000
```

`scripts/stress-test.sh` and `scripts/test-cdk-synthesis.py` exercise more
configuration combinations without deploying; the Python matrix runs
`cfn-lint` against every synthesized template. The CI workflow is the
authoritative list of all checks.

## Upgrade review checklist

For each proposed dependency, platform, container, or action upgrade:

1. Confirm the latest stable release from the audit's cited source.
2. Check runtime and architecture compatibility, especially Python
   constraints, CDK CLI/library behavior, and Go directives.
3. Pin GitHub Actions to immutable commit SHAs with a version comment.
4. Update lockfiles using the native package manager.
5. Run focused tests, then the broad local validation relevant to the change.
6. Review synthesized CloudFormation changes and new `cdk-nag` findings.
7. Document a justified deferral instead of applying an unsafe upgrade.

## Release and CI

Keep commits reviewable and do not commit generated caches, local state, or
credentials. Before release, verify the fork and push target, run normal
validation, and use `.github/workflows/manual-release.yml`. Monitor ordinary
GitHub Actions checks until green or until a confirmed external service,
permission, or quota blocks progress.
