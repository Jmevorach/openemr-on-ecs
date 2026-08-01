# Maintainer Guide

This guide is the operational index for repository maintenance. It separates
offline validation from commands that read or change AWS. Routine CI and the
commands in the first sections do not deploy infrastructure.

## Supported toolchains

- Python 3.14 for the application and all Python checks, including `cfn-lint`
- Node.js 24
- Go 1.26 for `scripts/backup-tui`
- AWS CDK v2 CLI
- Docker with Buildx for local container validation and live E2E asset builds

Create a local environment:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
npm ci
```

The npm package is private and contains pinned AWS CDK, `cdk-assets`, and
cdk-dia CLIs used by synthesis, live E2E, and diagram generation.
Python production and development requirements are exact pins; update them
through the audited upgrade workflow rather than relying on floating CI ranges.

## Command safety

Commands fall into four classes:

1. **Offline/local-only:** tests, formatting checks, static analysis, version
   inventory, knowledge MCP, import inspection/planning, and timing-report
   regeneration. Commands that accept an output path or regenerate a report
   write only those documented local artifacts.
2. **Public network/read-only:** the online version audit.
3. **AWS/read-only:** import status and live E2E preflight. E2E preflight also
   performs local synthesis and template diffing but does not deploy.
4. **AWS-mutating:** normal CDK deployment, import execution/finalization/
   cleanup, and live E2E run/cleanup. Use these only under their documented
   approval and confirmation procedures.

No regular GitHub Actions workflow invokes the live E2E runner or import
execution.

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
committed SHA pins and that the current OpenEMR ARM64 image digest matches the
immutable repository pin.

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
  scripts/test-cdk-synthesis.py
.venv/bin/flake8 app.py openemr_ecs tests diagrams tools \
  scripts/test-cdk-synthesis.py \
  --max-line-length=120 --extend-ignore=E203,W503,E501
.venv/bin/isort --check-only app.py openemr_ecs tests diagrams tools \
  scripts/test-cdk-synthesis.py
.venv/bin/mypy app.py openemr_ecs diagrams tools/_shared.py \
  tools/version_audit tools/knowledge_mcp tools/openemr_import tools/live_e2e \
  tools/openemr-import-worker/worker.py tools/credential-rotation/src \
  scripts/test-cdk-synthesis.py \
  --ignore-missing-imports
.venv/bin/bandit -r app.py openemr_ecs diagrams tools \
  scripts/test-cdk-synthesis.py -ll
.venv/bin/pip-audit --strict --progress-spinner off \
  -r requirements.txt -r requirements-dev.txt \
  -r tools/credential-rotation/requirements.txt \
  -r tools/openemr-import-worker/requirements.txt
npm audit --audit-level=high
.venv/bin/pre-commit run --all-files
```

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
configuration combinations and remain synthesis-only. The CI workflow is the
authoritative list of all checks, including Compose and CloudFormation lint.

## Read-only knowledge MCP

Use [KNOWLEDGE-MCP.md](KNOWLEDGE-MCP.md) for client configuration, the complete
tool and resource inventory, safety boundaries, examples, and troubleshooting.

Start the local STDIO server:

```bash
.venv/bin/python -m tools.knowledge_mcp
```

Configure an MCP client to launch that command with this repository as its
working directory. The server exposes a project overview, architecture map,
curated topics, bounded repository search/read operations, declared-version
inventory, redacted CDK configuration, and operational-command discovery.

The server:

- accepts only local STDIO transport;
- has no write, shell, subprocess, AWS, or network tools;
- resolves paths within an allowlist and rejects traversal and symlinks;
- bounds file size, line count, query length, and result count; and
- redacts credential-like content and excludes secret-like paths.

Its normal retrieval behavior is covered by in-memory FastMCP protocol tests in
`tests/tools/test_knowledge_mcp.py`.

## Importing an installation

Use [IMPORTING-OPENEMR.md](IMPORTING-OPENEMR.md) for the supported source
policy, offline inspect/plan commands, threat model, guarded execution,
recovery, and cleanup. The architectural rationale is in
[ADR 0001](docs/adr/0001-guarded-openemr-import.md).

Inspection and planning are offline. Execution is intentionally limited to a
same-version native OpenEMR backup and a fresh, empty, non-production stack
deployed with `-c openemr_import_target=true`. Normal stacks emit a disabled
import-target mode and are rejected before quiescence.
Never use operator-declared source versions to bypass archive evidence.

## Live deployment E2E and timing

Use [LIVE-E2E.md](LIVE-E2E.md) for profiles, preflight, exact confirmations,
deployment validation, failure behavior, and interrupted-run cleanup.

The implementation and normal CI stop before any live run. A run requires a
fresh preflight artifact, a clean committed worktree, a local interactive
terminal, explicit account/run confirmations, and the matching
`OPENEMR_LIVE_E2E_APPROVED_RUN_ID` environment value. Do not run it without the
documented human approval.

Regenerate the sanitized report locally:

```bash
.venv/bin/python -m tools.live_e2e report
```

`e2e-results/history.json` is the machine-readable source of truth and
`docs/deployment-timing.md` is generated from it. Commit them together after an
approved run. Raw run state under `.live-e2e/` can contain AWS identifiers and
must remain untracked.

## Upgrade review checklist

For each proposed dependency, platform, container, or action upgrade:

1. Confirm the latest stable release from the audit's cited source.
2. Check runtime and architecture compatibility, especially ARM64 image
   manifests, Python constraints, CDK CLI/library behavior, and Go directives.
3. Pin GitHub Actions to immutable commit SHAs with a version comment.
4. Update lockfiles using the native package manager.
5. Run focused tests, then the broad local validation relevant to the change.
6. Review synthesized CloudFormation changes and new `cdk-nag` findings.
7. Document a justified deferral instead of applying an unsafe upgrade.

## Release and CI

Keep commits reviewable and do not commit generated caches, local state,
credentials, migration bundles, patient data, or live E2E raw evidence.
Before release, verify the fork and push target, run normal validation, and use
`.github/workflows/manual-release.yml`. Monitor ordinary GitHub Actions checks
until green or until a confirmed external service, permission, or quota blocks
progress.
