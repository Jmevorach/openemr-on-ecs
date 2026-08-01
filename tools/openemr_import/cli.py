"""Command-line interface for offline planning and guarded AWS execution."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from tools._shared import ToolError, atomic_write_json, ensure_owner_only_directory, repository_root

from .aws import AwsImportError
from .inspect import inspect_source
from .models import ImportPlan
from .plan import TARGET_OPENEMR_VERSION, create_plan, inspection_from_dict, plan_from_dict

MAX_JSON_BYTES = 5 * 1024 * 1024


def _json_file(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise ToolError(f"Input is not a regular JSON file: {path}")
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ToolError(f"JSON input exceeds {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ToolError(f"Invalid UTF-8 JSON input: {path}") from exc
    if not isinstance(value, dict):
        raise ToolError("JSON input must contain one object")
    return value


def _emit(value: dict[str, Any], output: Path | None) -> None:
    if output:
        atomic_write_json(output, value)
    else:
        print(json.dumps(value, indent=2, sort_keys=True))


def _state_path(migration_id: str) -> Path:
    return repository_root() / ".openemr-import" / f"{migration_id}.json"


def _boto3_session(*, profile: str | None, region: str) -> Any:
    try:
        import boto3
    except ImportError as exc:
        raise ToolError("AWS execution requires the project requirements to be installed") from exc
    return boto3.Session(profile_name=profile, region_name=region)


def _assert_execution_confirmations(args: argparse.Namespace, plan: ImportPlan) -> None:
    required = {
        "--allow-aws-execution": args.allow_aws_execution,
        "--confirm-fresh-target": args.confirm_fresh_target,
        "--confirm-downtime": args.confirm_downtime,
        "--confirm-recovery-points": args.confirm_recovery_points,
        "--confirm-destructive-import": args.confirm_destructive_import,
    }
    missing = [flag for flag, accepted in required.items() if not accepted]
    if missing:
        raise ToolError("Execution is locked; explicit acknowledgements are missing: " + ", ".join(missing))
    expected = f"IMPORT:{args.account_id}:{args.region}:{args.stack_name}:" f"{plan.configuration_fingerprint}"
    if args.confirmation_token != expected:
        raise ToolError("Confirmation token mismatch. After reviewing the plan and target, pass: " + expected)


def _matching_plan_source(plan: ImportPlan, source: Path) -> None:
    if source.is_symlink() or not source.is_file():
        raise ToolError("Execution source must be one regular native backup file")
    inspection = inspect_source(
        source,
        source_version=plan.source_openemr_version,
    )
    comparisons = {
        "source kind": (inspection.source_kind, plan.source_kind),
        "source fingerprint": (
            inspection.source_fingerprint,
            plan.source_fingerprint,
        ),
        "component checksums": (inspection.checksums, plan.checksums),
        "source version": (
            inspection.source_openemr_version,
            plan.source_openemr_version,
        ),
    }
    mismatches = [label for label, (actual, expected) in comparisons.items() if actual != expected]
    if mismatches:
        raise ToolError("Source no longer matches the approved plan: " + ", ".join(mismatches))
    recomputed = create_plan(
        inspection,
        target_version=plan.target_openemr_version,
        generated_at=plan.created_at,
    )
    if recomputed != plan:
        raise ToolError("Import plan does not match current compatibility policy; regenerate it")


def _context_matches_receipt(context: Any, receipt: Any) -> None:
    comparisons = {
        "account": (context.account_id, receipt.account_id),
        "region": (context.region, receipt.region),
        "stack": (context.stack_name, receipt.stack_name),
        "cluster": (context.cluster_name, receipt.cluster_name),
        "service": (context.service_name, receipt.service_name),
        "service URL": (context.service_url, receipt.service_url),
        "OpenEMR version": (context.openemr_version, receipt.openemr_version),
        "task definition": (
            context.task_definition_arn,
            receipt.task_definition_arn,
        ),
        "staging bucket": (context.staging_bucket, receipt.staging_bucket),
    }
    mismatches = [name for name, (actual, expected) in comparisons.items() if actual != expected]
    if mismatches:
        raise ToolError("Current stack no longer matches the execution receipt: " + ", ".join(mismatches))


def _inspect_command(args: argparse.Namespace) -> int:
    inspection = inspect_source(
        args.source,
        source_version=args.source_version,
    )
    _emit(inspection.to_dict(), args.output)
    return 0


def _plan_command(args: argparse.Namespace) -> int:
    inspection = inspection_from_dict(_json_file(args.inspection))
    plan = create_plan(
        inspection,
        target_version=args.target_version,
    )
    _emit(plan.to_dict(), args.output)
    return 0 if plan.execution_allowed else 2


def _execute_command(args: argparse.Namespace) -> int:
    from .aws import (
        acquire_import_lock,
        assert_application_healthy,
        assert_service_autoscaling_active,
        assert_service_stable,
        cleanup_staging_scope,
        read_remote_status,
        recent_recovery_points,
        release_import_lock,
        resolve_stack_context,
        set_service_autoscaling_suspended,
        set_service_desired_count,
        start_import_task,
        upload_source,
        wait_for_task,
        write_receipt,
    )

    plan = plan_from_dict(_json_file(args.plan))
    if not plan.execution_allowed:
        raise ToolError("The approved plan blocks execution: " + "; ".join(plan.blockers))
    if plan.target_mode != "fresh-target-only":
        raise ToolError("Only fresh-target import plans can execute")
    if not re.fullmatch(r"\d{12}", args.account_id):
        raise ToolError("AWS account ID must contain exactly 12 digits")
    if args.maximum_recovery_age_hours < 1 or args.maximum_wait_attempts < 1:
        raise ToolError("Recovery age and waiter attempts must be positive")
    _assert_execution_confirmations(args, plan)
    _matching_plan_source(plan, args.source)
    state_path = args.state or _state_path(plan.migration_id)
    ensure_owner_only_directory(
        state_path.parent,
        parents=True,
        label="OpenEMR import state",
    )
    try:
        descriptor = os.open(state_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ToolError(f"Execution state already exists; inspect it before retrying: {state_path}") from exc
    with os.fdopen(descriptor, "w", encoding="utf-8") as reservation:
        reservation.write(
            json.dumps(
                {
                    "schema_version": 1,
                    "migration_id": plan.migration_id,
                    "status": "reserved",
                }
            )
            + "\n"
        )
    session = _boto3_session(profile=args.profile, region=args.region)
    context = None
    source_key = None
    quiesced = False
    lock_acquired = False
    launch_attempted = False
    receipt = None
    prelaunch_state: dict[str, Any] = {}
    try:
        context = resolve_stack_context(
            session=session,
            region=args.region,
            expected_account_id=args.account_id,
            stack_name=args.stack_name,
        )
        if context.openemr_version != plan.target_openemr_version:
            raise ToolError("Deployed OpenEMR version does not match the approved import plan")
        if context.import_target_mode != "fresh-target-only":
            raise ToolError(
                "Stack is not marked as a fresh import target; redeploy it with "
                "-c openemr_import_target=true before execution"
            )
        original_desired_count = assert_service_stable(context, session=session)
        assert_service_autoscaling_active(context, session=session)
        recovery_points = recent_recovery_points(
            context,
            session=session,
            maximum_age_hours=args.maximum_recovery_age_hours,
        )
        prelaunch_state = {
            "schema_version": 1,
            "migration_id": plan.migration_id,
            "status": "recovery-verified",
            "account_id": context.account_id,
            "region": context.region,
            "stack_name": context.stack_name,
            "cluster_name": context.cluster_name,
            "service_name": context.service_name,
            "service_url": context.service_url,
            "openemr_version": context.openemr_version,
            "original_desired_count": original_desired_count,
            "task_definition_arn": context.task_definition_arn,
            "staging_bucket": context.staging_bucket,
            "source_key": None,
            "recovery_point_arns": [point.recovery_point_arn for point in recovery_points],
            "recovery_point_dates": [point.creation_date for point in recovery_points],
            "started_by": plan.migration_id,
            "service_remains_stopped": False,
            "autoscaling_remains_suspended": False,
        }
        atomic_write_json(state_path, prelaunch_state)
        acquire_import_lock(
            context,
            session=session,
            migration_id=plan.migration_id,
        )
        lock_acquired = True
        prelaunch_state["status"] = "lock-acquired"
        atomic_write_json(state_path, prelaunch_state)
        source_key = upload_source(
            context,
            session=session,
            migration_id=plan.migration_id,
            source=args.source,
        )
        prelaunch_state["status"] = "source-staged"
        prelaunch_state["source_key"] = source_key
        atomic_write_json(state_path, prelaunch_state)
        quiesced = True
        set_service_autoscaling_suspended(
            context,
            session=session,
            suspended=True,
        )
        set_service_desired_count(
            context,
            session=session,
            desired_count=0,
        )
        launch_attempted = True
        try:
            receipt = start_import_task(
                context,
                session=session,
                plan=plan,
                migration_id=plan.migration_id,
                source_key=source_key,
                original_desired_count=original_desired_count,
                recovery_points=recovery_points,
            )
        except BotoCoreError:
            receipt = start_import_task(
                context,
                session=session,
                plan=plan,
                migration_id=plan.migration_id,
                source_key=source_key,
                original_desired_count=original_desired_count,
                recovery_points=recovery_points,
            )
    except (BotoCoreError, KeyboardInterrupt) as exc:
        if launch_attempted:
            atomic_write_json(
                state_path,
                {
                    **prelaunch_state,
                    "status": "launch-outcome-unknown",
                    "service_remains_stopped": True,
                    "autoscaling_remains_suspended": True,
                },
            )
            raise ToolError(
                "ECS task launch outcome is unknown. The service remains stopped, "
                "autoscaling remains suspended, and staging data is preserved; "
                f"reconcile ECS startedBy={plan.migration_id} "
                f"before using state file {state_path}"
            ) from exc
        if quiesced and context is not None:
            try:
                set_service_desired_count(
                    context,
                    session=session,
                    desired_count=original_desired_count,
                )
            finally:
                set_service_autoscaling_suspended(
                    context,
                    session=session,
                    suspended=False,
                )
        if source_key is not None and context is not None:
            cleanup_staging_scope(
                region=context.region,
                staging_bucket=context.staging_bucket,
                migration_id=plan.migration_id,
                session=session,
            )
        if lock_acquired and context is not None:
            release_import_lock(
                context,
                session=session,
                migration_id=plan.migration_id,
            )
        state_path.unlink(missing_ok=True)
        raise
    except Exception as exc:
        if launch_attempted:
            atomic_write_json(
                state_path,
                {
                    **prelaunch_state,
                    "status": "launch-outcome-unknown",
                    "service_remains_stopped": True,
                    "autoscaling_remains_suspended": True,
                },
            )
            raise ToolError(
                "ECS task launch outcome is unknown. The service remains stopped, "
                "autoscaling remains suspended, and staging data is preserved; "
                f"reconcile ECS startedBy={plan.migration_id} "
                f"before using state file {state_path}"
            ) from exc
        if quiesced and context is not None:
            try:
                set_service_desired_count(
                    context,
                    session=session,
                    desired_count=original_desired_count,
                )
            finally:
                set_service_autoscaling_suspended(
                    context,
                    session=session,
                    suspended=False,
                )
        if source_key is not None and context is not None:
            cleanup_staging_scope(
                region=context.region,
                staging_bucket=context.staging_bucket,
                migration_id=plan.migration_id,
                session=session,
            )
        if lock_acquired and context is not None:
            release_import_lock(
                context,
                session=session,
                migration_id=plan.migration_id,
            )
        state_path.unlink(missing_ok=True)
        raise

    assert context is not None and receipt is not None
    write_receipt(state_path, receipt)
    exit_code = wait_for_task(
        context,
        session=session,
        task_arn=receipt.task_arn,
        maximum_attempts=args.maximum_wait_attempts,
    )
    status = read_remote_status(receipt, session=session)
    worker_status = status.get("worker", {}).get("status")
    if exit_code == 0 and worker_status == "succeeded":
        set_service_desired_count(
            context,
            session=session,
            desired_count=original_desired_count,
        )
        try:
            assert_application_healthy(context)
        except Exception:
            set_service_desired_count(
                context,
                session=session,
                desired_count=0,
            )
            raise
        set_service_autoscaling_suspended(
            context,
            session=session,
            suspended=False,
        )
        status = read_remote_status(receipt, session=session)
        status["result"] = "import-succeeded-service-restored"
        status["state_file"] = str(state_path)
        _emit(status, None)
        return 0
    status["result"] = "import-failed-service-remains-stopped"
    status["state_file"] = str(state_path)
    _emit(status, None)
    return 3


def _status_command(args: argparse.Namespace) -> int:
    from .aws import read_receipt, read_remote_status

    receipt = read_receipt(args.state)
    session = _boto3_session(profile=args.profile, region=receipt.region)
    _emit(read_remote_status(receipt, session=session), None)
    return 0


def _finalize_command(args: argparse.Namespace) -> int:
    from .aws import (
        assert_application_healthy,
        read_receipt,
        read_remote_status,
        resolve_stack_context,
        set_service_autoscaling_suspended,
        set_service_desired_count,
    )

    receipt = read_receipt(args.state)
    expected = f"FINALIZE:{receipt.migration_id}"
    if not args.allow_aws_execution or args.confirmation_token != expected:
        raise ToolError("Finalization requires --allow-aws-execution and --confirmation-token " + expected)
    session = _boto3_session(profile=args.profile, region=receipt.region)
    context = resolve_stack_context(
        session=session,
        region=receipt.region,
        expected_account_id=receipt.account_id,
        stack_name=receipt.stack_name,
    )
    _context_matches_receipt(context, receipt)
    status = read_remote_status(receipt, session=session)
    if not _completed_worker_success(status):
        raise ToolError("The import worker did not report success; do not restart service")
    set_service_desired_count(
        context,
        session=session,
        desired_count=receipt.original_desired_count,
    )
    try:
        assert_application_healthy(context)
    except Exception:
        set_service_desired_count(
            context,
            session=session,
            desired_count=0,
        )
        raise
    set_service_autoscaling_suspended(
        context,
        session=session,
        suspended=False,
    )
    _emit(read_remote_status(receipt, session=session), None)
    return 0


def _cleanup_command(args: argparse.Namespace) -> int:
    from .aws import (
        assert_application_healthy,
        cleanup_staging,
        read_receipt,
        read_remote_status,
        release_import_lock,
        resolve_stack_context,
        start_cleanup_task,
        wait_for_task,
    )

    receipt = read_receipt(args.state)
    expected = f"CLEANUP:{receipt.migration_id}"
    if not args.allow_aws_execution or not args.confirm_delete_rollback_copy or args.confirmation_token != expected:
        raise ToolError(
            "Cleanup requires --allow-aws-execution, "
            "--confirm-delete-rollback-copy, and --confirmation-token " + expected
        )
    session = _boto3_session(profile=args.profile, region=receipt.region)
    context = resolve_stack_context(
        session=session,
        region=receipt.region,
        expected_account_id=receipt.account_id,
        stack_name=receipt.stack_name,
    )
    _context_matches_receipt(context, receipt)
    status = read_remote_status(receipt, session=session)
    if not _completed_worker_success(status):
        raise ToolError("Cleanup is allowed only after a successful import")
    service = status.get("service", {})
    if (
        service.get("desired_count") != receipt.original_desired_count
        or service.get("running_count") != receipt.original_desired_count
    ):
        raise ToolError("Cleanup requires the restored service to be fully running")
    if status.get("autoscaling", {}).get("active") is not True:
        raise ToolError("Cleanup requires ECS service autoscaling to be active")
    assert_application_healthy(context)
    task_arn = start_cleanup_task(
        context,
        session=session,
        migration_id=receipt.migration_id,
    )
    if wait_for_task(context, session=session, task_arn=task_arn) != 0:
        raise ToolError("EFS import-artifact cleanup task failed")
    deleted = cleanup_staging(receipt, session=session)
    release_import_lock(
        context,
        session=session,
        migration_id=receipt.migration_id,
    )
    args.state.unlink()
    _emit(
        {
            "schema_version": 1,
            "migration_id": receipt.migration_id,
            "status": "cleanup-complete",
            "s3_objects_deleted": deleted,
            "local_state_deleted": True,
            "efs_rollback_copy_deleted": True,
        },
        None,
    )
    return 0


def _completed_worker_success(status: dict[str, Any]) -> bool:
    worker = status.get("worker", {})
    task = status.get("task", {})
    return (
        isinstance(worker, dict)
        and worker.get("status") == "succeeded"
        and isinstance(task, dict)
        and task.get("last_status") == "STOPPED"
        and task.get("container_exit_code") == 0
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m tools.openemr_import",
        description=(
            "Inspect and plan offline by default; AWS mutations require explicit "
            "execution subcommands and confirmations."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser("inspect")
    inspect_parser.add_argument("source", type=Path)
    inspect_parser.add_argument("--source-version")
    inspect_parser.add_argument("--output", type=Path)
    inspect_parser.set_defaults(handler=_inspect_command)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("inspection", type=Path)
    plan_parser.add_argument("--target-version", default=TARGET_OPENEMR_VERSION)
    plan_parser.add_argument("--output", type=Path)
    plan_parser.set_defaults(handler=_plan_command)

    execute_parser = subparsers.add_parser("execute")
    execute_parser.add_argument("--plan", type=Path, required=True)
    execute_parser.add_argument("--source", type=Path, required=True)
    execute_parser.add_argument("--account-id", required=True)
    execute_parser.add_argument("--region", required=True)
    execute_parser.add_argument("--stack-name", required=True)
    execute_parser.add_argument("--profile")
    execute_parser.add_argument("--state", type=Path)
    execute_parser.add_argument("--maximum-recovery-age-hours", type=int, default=36)
    execute_parser.add_argument("--maximum-wait-attempts", type=int, default=960)
    execute_parser.add_argument("--allow-aws-execution", action="store_true")
    execute_parser.add_argument("--confirm-fresh-target", action="store_true")
    execute_parser.add_argument("--confirm-downtime", action="store_true")
    execute_parser.add_argument("--confirm-recovery-points", action="store_true")
    execute_parser.add_argument("--confirm-destructive-import", action="store_true")
    execute_parser.add_argument("--confirmation-token", required=True)
    execute_parser.set_defaults(handler=_execute_command)

    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--state", type=Path, required=True)
    status_parser.add_argument("--profile")
    status_parser.set_defaults(handler=_status_command)

    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--state", type=Path, required=True)
    finalize_parser.add_argument("--profile")
    finalize_parser.add_argument("--allow-aws-execution", action="store_true")
    finalize_parser.add_argument("--confirmation-token", required=True)
    finalize_parser.set_defaults(handler=_finalize_command)

    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--state", type=Path, required=True)
    cleanup_parser.add_argument("--profile")
    cleanup_parser.add_argument("--allow-aws-execution", action="store_true")
    cleanup_parser.add_argument(
        "--confirm-delete-rollback-copy",
        action="store_true",
    )
    cleanup_parser.add_argument("--confirmation-token", required=True)
    cleanup_parser.set_defaults(handler=_cleanup_command)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the import CLI with redacted, actionable failures."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (AwsImportError, ToolError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "unknown")
        print(f"error: AWS API request failed ({code})", file=sys.stderr)
        return 2
    except BotoCoreError:
        print("error: AWS SDK operation failed", file=sys.stderr)
        return 2
