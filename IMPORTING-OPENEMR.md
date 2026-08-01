# Importing an Existing OpenEMR Installation

The import utility is conservative by design. Inspection and planning are local,
offline, read-only operations. AWS access is available only through explicit
execution, finalization, status, and cleanup commands.

No import has been run as part of implementing this utility.

The architecture and rejected alternatives are recorded in
[ADR 0001](docs/adr/0001-guarded-openemr-import.md).

## First-release support policy

Automatic execution supports only all of the following:

- one native OpenEMR backup archive produced by `interface/main/backup.php`;
- a stable source whose `version.php` exactly matches the deployed OpenEMR
  container version;
- one site named `default`;
- a recognizable MySQL or MariaDB logical dump;
- both OpenEMR document-encryption key files (`sixa` and `sixb`);
- a newly initialized, non-production target with no patients, encounters, or
  documents; and
- recent completed AWS Backup recovery points for both Aurora and the sites EFS
  file system.

The utility inspects directory and manifest bundles, but does not execute them.
It also refuses upgrades, downgrades, multisite imports, missing encryption
keys, custom executable content in imported data, prerelease versions,
PostgreSQL, and in-place imports into used targets.

These limits are intentional. Cross-version migrations must first use
OpenEMR's supported upgrade path outside this utility.

## What is imported

The worker imports the logical database and a narrow site-data allowlist:

- `sites/default/documents`
- `sites/default/images`
- `sites/default/LBF`
- the standard click, fax, and referral template files

The deployed target's `sqlconf.php`, application configuration, server-control
files, and RDS CA material are preserved. Source application files and source
database credentials are never copied. Script-like files inside imported data
cause execution to stop.

The policy follows the native backup structure in the pinned upstream
[`backup.php`](https://github.com/openemr/openemr/blob/6125a2fd8089c8bcc3848071c1293c60e27a7585/interface/main/backup.php).
The same-version restriction avoids invoking undocumented upgrade behavior
during an infrastructure import.

## Offline workflow

Install development dependencies in an isolated environment:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
```

Inspect the source without extracting its file trees and without AWS calls,
subprocesses, or network access:

```bash
.venv/bin/python -m tools.openemr_import inspect \
  /secure/path/openemr-backup.tar \
  --output /secure/path/inspection.json
```

The inspection report contains aggregate counts, versions, checksums, and
policy findings. It never contains SQL, archive member names, document content,
credentials, or patient values.

Create a deterministic review artifact:

```bash
.venv/bin/python -m tools.openemr_import plan \
  /secure/path/inspection.json \
  --output /secure/path/import-plan.json
```

An exit status of `2` means the plan was generated but blocks execution. Review
`blockers`, `warnings`, `preconditions`, and `rollback` before proceeding.

## Deployment prerequisites

Deploy a new, non-production target with the explicit import-target marker:

```bash
node_modules/.bin/cdk deploy -c openemr_import_target=true
```

Normal stacks emit `OpenEMRImportTargetMode=disabled`, and the executor refuses
them even if every CLI confirmation is supplied. The import-target deployment
adds:

- a dormant ARM64 Fargate task definition (it never runs automatically);
- a private, versioned, KMS-encrypted S3 staging bucket with a one-day current
  and noncurrent-version lifecycle;
- a 50 GiB ephemeral work volume;
- read/write access to only that staging bucket;
- an import-only EFS access point plus a write/rename probe that must pass
  before any database replacement; and
- CloudFormation outputs used to bind the CLI to one account, region, and
  stack.

The operator needs narrowly scoped permission to:

- read the named CloudFormation stack and caller identity;
- read ECS service/task status, suspend and resume that service's Application
  Auto Scaling target, update its desired count, and run the emitted import
  task definition with `iam:PassRole`
  (`application-autoscaling:DescribeScalableTargets` and
  `application-autoscaling:RegisterScalableTarget`);
- read AWS Backup recovery points for the emitted Aurora and EFS ARNs; and
- conditionally create and owner-check `locks/active.json`, read/write the
  emitted migration staging prefix, list its object versions, and delete
  versions only under that prefix, with encrypt/decrypt/data-key access to the
  emitted staging KMS key ARN.

Do not grant broad administrator access solely for this workflow.

## Explicit execution

Execution causes downtime and destructive database replacement. It first
re-inspects the source, verifies the plan byte-for-byte against current policy,
checks account/region/stack/version/import-target mode, verifies current
recovery points, acquires a stack-wide conditional lock, uploads the source
with KMS encryption, fully suspends desired-count scaling, and stops the
OpenEMR service. The worker then revalidates checksums and archive safety,
rejects SQL client commands while enabling MariaDB sandbox and binary modes,
proves representative clinical and operational tables are unused, imports the
database, atomically swaps the site directory, and validates the result.

The exact confirmation token is:

```text
IMPORT:<account-id>:<region>:<stack-name>:<configuration_fingerprint>
```

After the mandatory approval checkpoint, execution has this form:

```bash
.venv/bin/python -m tools.openemr_import execute \
  --plan /secure/path/import-plan.json \
  --source /secure/path/openemr-backup.tar \
  --account-id 123456789012 \
  --region us-east-1 \
  --stack-name OpenEMR \
  --profile approved-profile \
  --allow-aws-execution \
  --confirm-fresh-target \
  --confirm-downtime \
  --confirm-recovery-points \
  --confirm-destructive-import \
  --confirmation-token 'IMPORT:123456789012:us-east-1:OpenEMR:<fingerprint>'
```

The command waits for the task. On success it restores the original ECS desired
count, checks the HTTPS login page, and resumes autoscaling. On a worker or
health failure, the service remains stopped and autoscaling remains suspended,
so the configured minimum capacity cannot restart tasks during database or EFS
mutation. If task-launch status is uncertain, the deterministic ECS `startedBy`
value is the migration ID; reconcile it before any recovery action.

Local execution receipts are mode `0600` under `.openemr-import/`, which is
gitignored. They contain resource identifiers and recovery-point references,
but no credentials or health data.

## Status, recovery, and finalization

Status is read-only:

```bash
.venv/bin/python -m tools.openemr_import status \
  --state .openemr-import/import-<id>.json \
  --profile approved-profile
```

If the import task succeeded but the original execute process was interrupted,
restart and health-check the service explicitly:

```bash
.venv/bin/python -m tools.openemr_import finalize \
  --state .openemr-import/import-<id>.json \
  --profile approved-profile \
  --allow-aws-execution \
  --confirmation-token 'FINALIZE:import-<id>'
```

Never finalize a failed or uncertain import. Keep the service stopped and
restore the recovery-point ARNs recorded in the local receipt:

1. restore Aurora and EFS using the repository backup/restore procedure;
2. verify the restored database and `sites/default` tree;
3. restore the ECS desired count while autoscaling remains suspended;
4. verify the HTTPS login page and application behavior;
5. resume ECS service autoscaling; and
6. retain the failed staging evidence until the incident is understood.

The worker also keeps the original EFS `default` directory under a
migration-scoped rollback path. This is a convenience copy, not a replacement
for AWS Backup.

## Cleanup

Cleanup permanently deletes the migration's EFS rollback copy, every version
and delete marker for its S3 source and status objects, releases the
owner-checked stack-wide lock, and deletes the local receipt.
It is allowed only after the worker reports success, the original ECS task
count is restored, autoscaling is active, and the HTTPS login page is healthy:

```bash
.venv/bin/python -m tools.openemr_import cleanup \
  --state .openemr-import/import-<id>.json \
  --profile approved-profile \
  --allow-aws-execution \
  --confirm-delete-rollback-copy \
  --confirmation-token 'CLEANUP:import-<id>'
```

After cleanup, update the stack with `-c openemr_import_target=false` so future
imports remain disabled unless a maintainer deliberately marks another fresh
target.

Keep the original source backup in approved secure storage according to the
organization's retention and PHI-handling policy.

## Security notes

- Run inspection on an encrypted local volume with restrictive permissions.
- Treat the source archive as PHI even though generated reports are redacted.
- The implementation rejects traversal, absolute paths, case collisions,
  duplicate members, links, devices, FIFOs, oversized members, archive bombs,
  malformed compression, and encrypted zip members.
- Database credentials come from ECS Secrets Manager integration and never
  appear in task commands or logs.
- The worker uses the administrator credential only to recreate the target
  schema and provision a temporary TLS-only, target-schema-scoped import user;
  source SQL runs as that limited user, which is deleted afterward.
- Database connections require the AWS RDS CA and certificate verification.
- The task receives no public IP and runs only in the stack's private subnets.
- The import utility never executes source application code.
