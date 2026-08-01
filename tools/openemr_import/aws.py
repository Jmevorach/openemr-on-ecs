"""Narrow AWS adapter for explicitly approved import execution."""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin, urlparse

import requests
from botocore.exceptions import ClientError

from tools._shared import atomic_write_json, ensure_owner_only_directory

from .models import ImportPlan


class AwsImportError(RuntimeError):
    """Raised when an AWS-side import safeguard or operation fails."""


@dataclass(frozen=True)
class StackContext:
    """Deployment details resolved from one explicit CloudFormation stack."""

    account_id: str
    region: str
    stack_name: str
    cluster_name: str
    service_name: str
    service_url: str
    openemr_version: str
    import_target_mode: str
    task_definition_arn: str
    staging_bucket: str
    staging_kms_key_arn: str
    task_security_group_id: str
    private_subnet_ids: tuple[str, ...]
    database_arn: str
    efs_arn: str


@dataclass(frozen=True)
class RecoveryPoint:
    """A recent completed AWS Backup recovery point."""

    resource_arn: str
    recovery_point_arn: str
    creation_date: str


@dataclass(frozen=True)
class ExecutionReceipt:
    """Minimal non-secret execution state persisted locally."""

    schema_version: int
    migration_id: str
    account_id: str
    region: str
    stack_name: str
    cluster_name: str
    service_name: str
    service_url: str
    openemr_version: str
    original_desired_count: int
    task_arn: str
    task_definition_arn: str
    staging_bucket: str
    source_key: str
    started_at: str
    recovery_point_arns: tuple[str, str]
    recovery_point_dates: tuple[str, str]


REQUIRED_OUTPUTS = {
    "ECSClusterName",
    "ECSServiceName",
    "ApplicationURL",
    "OpenEMRVersion",
    "OpenEMRImportTargetMode",
    "OpenEMRImportTaskDefinitionArn",
    "OpenEMRImportStagingBucketName",
    "OpenEMRImportStagingKmsKeyArn",
    "OpenEMRImportSecurityGroupId",
    "PrivateSubnetIds",
    "DatabaseClusterArn",
    "EFSSitesFileSystemId",
}
IMPORT_LOCK_KEY = "locks/active.json"


def _client(factory: Callable[..., Any], service: str, region: str) -> Any:
    return factory(service, region_name=region)


def _scalable_resource_id(cluster_name: str, service_name: str) -> str:
    return f"service/{cluster_name}/{service_name}"


def _service_scalable_target(
    *,
    region: str,
    cluster_name: str,
    service_name: str,
    session: Any,
) -> dict[str, Any]:
    client = _client(session.client, "application-autoscaling", region)
    response = client.describe_scalable_targets(
        ServiceNamespace="ecs",
        ResourceIds=[_scalable_resource_id(cluster_name, service_name)],
        ScalableDimension="ecs:service:DesiredCount",
    )
    targets = response.get("ScalableTargets", [])
    if len(targets) != 1 or not isinstance(targets[0], dict):
        raise AwsImportError("Expected exactly one ECS service autoscaling target")
    target = dict(targets[0])
    minimum = target.get("MinCapacity")
    maximum = target.get("MaxCapacity")
    if (
        isinstance(minimum, bool)
        or not isinstance(minimum, int)
        or isinstance(maximum, bool)
        or not isinstance(maximum, int)
        or minimum < 1
        or maximum < minimum
    ):
        raise AwsImportError("ECS service autoscaling capacity bounds are invalid")
    return target


def _suspension_states(target: dict[str, Any]) -> dict[str, bool]:
    state = target.get("SuspendedState", {})
    if not isinstance(state, dict):
        raise AwsImportError("ECS service autoscaling suspension state is invalid")
    keys = (
        "DynamicScalingInSuspended",
        "DynamicScalingOutSuspended",
        "ScheduledScalingSuspended",
    )
    values = {key: state.get(key, False) for key in keys}
    if any(not isinstance(value, bool) for value in values.values()):
        raise AwsImportError("ECS service autoscaling suspension state is invalid")
    return values


def resolve_stack_context(
    *,
    session: Any,
    region: str,
    expected_account_id: str,
    stack_name: str,
) -> StackContext:
    """Resolve and bind execution to one explicit account, region, and stack."""

    if session.region_name and session.region_name != region:
        raise AwsImportError(f"Session region {session.region_name!r} does not match expected region {region!r}")
    sts = _client(session.client, "sts", region)
    identity = sts.get_caller_identity()
    account_id = str(identity.get("Account", ""))
    if account_id != expected_account_id:
        raise AwsImportError(f"Caller account {account_id!r} does not match {expected_account_id!r}")

    cloudformation = _client(session.client, "cloudformation", region)
    response = cloudformation.describe_stacks(StackName=stack_name)
    stacks = response.get("Stacks", [])
    if len(stacks) != 1:
        raise AwsImportError(f"Expected exactly one stack named {stack_name!r}")
    stack = stacks[0]
    status = str(stack.get("StackStatus", ""))
    if status not in {
        "CREATE_COMPLETE",
        "IMPORT_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
    }:
        raise AwsImportError(f"Stack is not stable: {status or 'unknown'}")
    outputs = {
        item["OutputKey"]: item["OutputValue"]
        for item in stack.get("Outputs", [])
        if item.get("OutputKey") and item.get("OutputValue")
    }
    missing = sorted(REQUIRED_OUTPUTS - outputs.keys())
    if missing:
        raise AwsImportError("Stack predates import support or is incomplete; missing outputs: " + ", ".join(missing))
    if outputs["OpenEMRImportTargetMode"] not in {"disabled", "fresh-target-only"}:
        raise AwsImportError("Stack returned an invalid OpenEMR import-target mode")
    stack_id = str(stack.get("StackId", ""))
    stack_parts = stack_id.split(":", 5)
    if (
        len(stack_parts) != 6
        or stack_parts[2] != "cloudformation"
        or stack_parts[3] != region
        or stack_parts[4] != account_id
        or not stack_parts[5].startswith(f"stack/{stack_name}/")
    ):
        raise AwsImportError("Resolved stack identity does not match the requested target")
    partition = stack_parts[1]
    filesystem_id = outputs["EFSSitesFileSystemId"]
    if not filesystem_id.startswith("fs-"):
        raise AwsImportError("Invalid EFS file-system output")
    private_subnet_ids = tuple(value for value in outputs["PrivateSubnetIds"].split(",") if value)
    if not private_subnet_ids or any(not re.fullmatch(r"subnet-[0-9a-f]+", value) for value in private_subnet_ids):
        raise AwsImportError("Invalid private-subnet output")
    staging_kms_key_arn = outputs["OpenEMRImportStagingKmsKeyArn"]
    kms_parts = staging_kms_key_arn.split(":", 5)
    if (
        len(kms_parts) != 6
        or kms_parts[1] != partition
        or kms_parts[2] != "kms"
        or kms_parts[3] != region
        or kms_parts[4] != account_id
        or not re.fullmatch(r"key/[0-9a-f-]+", kms_parts[5])
    ):
        raise AwsImportError("Invalid import staging KMS key output")
    return StackContext(
        account_id=account_id,
        region=region,
        stack_name=stack_name,
        cluster_name=outputs["ECSClusterName"],
        service_name=outputs["ECSServiceName"],
        service_url=outputs["ApplicationURL"],
        openemr_version=outputs["OpenEMRVersion"],
        import_target_mode=outputs["OpenEMRImportTargetMode"],
        task_definition_arn=outputs["OpenEMRImportTaskDefinitionArn"],
        staging_bucket=outputs["OpenEMRImportStagingBucketName"],
        staging_kms_key_arn=staging_kms_key_arn,
        task_security_group_id=outputs["OpenEMRImportSecurityGroupId"],
        private_subnet_ids=private_subnet_ids,
        database_arn=outputs["DatabaseClusterArn"],
        efs_arn=f"arn:{partition}:elasticfilesystem:{region}:{account_id}:file-system/{filesystem_id}",
    )


def assert_service_stable(context: StackContext, *, session: Any) -> int:
    """Require the target service to be present and deployment-stable."""

    ecs = _client(session.client, "ecs", context.region)
    response = ecs.describe_services(
        cluster=context.cluster_name,
        services=[context.service_name],
    )
    failures = response.get("failures", [])
    services = response.get("services", [])
    if failures or len(services) != 1:
        raise AwsImportError("Unable to resolve the target OpenEMR service")
    service = services[0]
    deployments = service.get("deployments", [])
    if (
        service.get("status") != "ACTIVE"
        or len(deployments) != 1
        or deployments[0].get("rolloutState") != "COMPLETED"
        or service.get("runningCount") != service.get("desiredCount")
    ):
        raise AwsImportError("Target OpenEMR service is not deployment-stable")
    desired_count = service.get("desiredCount")
    if not isinstance(desired_count, int) or desired_count < 1:
        raise AwsImportError("Target OpenEMR service has no running application tasks")
    return desired_count


def assert_service_autoscaling_active(context: StackContext, *, session: Any) -> None:
    """Require the ECS desired-count scalable target to be fully active."""

    target = _service_scalable_target(
        region=context.region,
        cluster_name=context.cluster_name,
        service_name=context.service_name,
        session=session,
    )
    states = _suspension_states(target)
    if any(states.values()):
        raise AwsImportError("Target ECS service autoscaling is already suspended")


def set_service_autoscaling_suspended(
    context: StackContext,
    *,
    session: Any,
    suspended: bool,
) -> None:
    """Idempotently suspend or resume every scaling activity for one ECS service."""

    client = _client(session.client, "application-autoscaling", context.region)
    target = _service_scalable_target(
        region=context.region,
        cluster_name=context.cluster_name,
        service_name=context.service_name,
        session=session,
    )
    states = _suspension_states(target)
    if len(set(states.values())) != 1:
        raise AwsImportError("ECS service autoscaling has a mixed suspension state")
    if next(iter(states.values())) is suspended:
        return
    arguments: dict[str, Any] = {
        "ServiceNamespace": "ecs",
        "ResourceId": _scalable_resource_id(context.cluster_name, context.service_name),
        "ScalableDimension": "ecs:service:DesiredCount",
        "MinCapacity": int(target["MinCapacity"]),
        "MaxCapacity": int(target["MaxCapacity"]),
        "SuspendedState": {
            "DynamicScalingInSuspended": suspended,
            "DynamicScalingOutSuspended": suspended,
            "ScheduledScalingSuspended": suspended,
        },
    }
    client.register_scalable_target(**arguments)
    updated = _service_scalable_target(
        region=context.region,
        cluster_name=context.cluster_name,
        service_name=context.service_name,
        session=session,
    )
    if set(_suspension_states(updated).values()) != {suspended}:
        raise AwsImportError("ECS service autoscaling suspension change was not applied")


def set_service_desired_count(
    context: StackContext,
    *,
    session: Any,
    desired_count: int,
) -> None:
    """Set and wait for the target service's desired task count."""

    if desired_count < 0:
        raise ValueError("desired_count cannot be negative")
    ecs = _client(session.client, "ecs", context.region)
    ecs.update_service(
        cluster=context.cluster_name,
        service=context.service_name,
        desiredCount=desired_count,
    )
    waiter = ecs.get_waiter("services_stable")
    waiter.wait(
        cluster=context.cluster_name,
        services=[context.service_name],
        WaiterConfig={"Delay": 15, "MaxAttempts": 80},
    )


def assert_application_healthy(
    context: StackContext,
    *,
    attempts: int = 20,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """Require the public login page to become healthy after service restart."""

    parsed = urlparse(context.service_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise AwsImportError("Stack OpenEMR URL is not a safe HTTPS target")
    target = urljoin(
        context.service_url.rstrip("/") + "/",
        "interface/login/login.php?site=default",
    )
    for attempt in range(attempts):
        try:
            response = requests.get(
                target,
                headers={"User-Agent": "openemr-on-ecs-import-health/1"},
                timeout=20,
            )
            body = getattr(response, "text", "")
            if response.status_code == 200 and isinstance(body, str) and "openemr" in body[:200_000].lower():
                return
        except requests.RequestException:
            pass
        if attempt + 1 < attempts:
            sleep(15)
    raise AwsImportError("OpenEMR login page did not become healthy after import")


def recent_recovery_points(
    context: StackContext,
    *,
    session: Any,
    maximum_age_hours: int = 36,
    now: datetime | None = None,
) -> tuple[RecoveryPoint, RecoveryPoint]:
    """Require recent completed recovery points for Aurora and EFS."""

    backup = _client(session.client, "backup", context.region)
    threshold = (now or datetime.now(UTC)) - timedelta(hours=maximum_age_hours)
    points: list[RecoveryPoint] = []
    for resource_arn in (context.database_arn, context.efs_arn):
        candidates: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            arguments: dict[str, Any] = {
                "ResourceArn": resource_arn,
                "MaxResults": 100,
            }
            if token:
                arguments["NextToken"] = token
            response = backup.list_recovery_points_by_resource(**arguments)
            candidates.extend(
                item
                for item in response.get("RecoveryPoints", [])
                if item.get("Status") == "COMPLETED"
                and isinstance(item.get("CreationDate"), datetime)
                and item["CreationDate"] >= threshold
            )
            token = response.get("NextToken")
            if not token:
                break
        if not candidates:
            raise AwsImportError("No recent completed AWS Backup recovery point for " + resource_arn.split(":")[2])
        newest = max(candidates, key=lambda item: item["CreationDate"])
        points.append(
            RecoveryPoint(
                resource_arn=resource_arn,
                recovery_point_arn=newest["RecoveryPointArn"],
                creation_date=newest["CreationDate"].astimezone(UTC).isoformat(),
            )
        )
    return points[0], points[1]


def acquire_import_lock(
    context: StackContext,
    *,
    session: Any,
    migration_id: str,
) -> None:
    """Acquire the stack-wide import lock with one conditional S3 write."""

    s3 = _client(session.client, "s3", context.region)
    payload = json.dumps(
        {
            "schema_version": 1,
            "migration_id": migration_id,
            "created_at": datetime.now(UTC).isoformat(),
        },
        sort_keys=True,
    ).encode("utf-8")
    try:
        s3.put_object(
            Bucket=context.staging_bucket,
            Key=IMPORT_LOCK_KEY,
            Body=payload,
            ContentType="application/json",
            Metadata={"migration-id": migration_id},
            IfNoneMatch="*",
        )
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in {"ConditionalRequestConflict", "PreconditionFailed"} or status in {409, 412}:
            raise AwsImportError("Another import already holds the stack-wide lock") from exc
        raise


def release_import_lock(
    context: StackContext,
    *,
    session: Any,
    migration_id: str,
) -> None:
    """Release only the stack-wide lock owned by this migration."""

    s3 = _client(session.client, "s3", context.region)
    try:
        lock = s3.head_object(Bucket=context.staging_bucket, Key=IMPORT_LOCK_KEY)
    except ClientError as exc:
        if str(exc.response.get("Error", {}).get("Code", "")) in {"404", "NoSuchKey", "NotFound"}:
            return
        raise
    metadata = lock.get("Metadata", {})
    if not isinstance(metadata, dict) or metadata.get("migration-id") != migration_id:
        raise AwsImportError("Refusing to release an import lock owned by another migration")
    s3.delete_object(Bucket=context.staging_bucket, Key=IMPORT_LOCK_KEY)


def upload_source(
    context: StackContext,
    *,
    session: Any,
    migration_id: str,
    source: Path,
) -> str:
    """Upload the verified native backup under a migration-scoped key."""

    key = f"migrations/{migration_id}/source.tar"
    s3 = _client(session.client, "s3", context.region)
    existing = s3.list_object_versions(
        Bucket=context.staging_bucket,
        Prefix=f"migrations/{migration_id}/",
        MaxKeys=1,
    )
    if existing.get("Versions") or existing.get("DeleteMarkers"):
        raise AwsImportError("Migration staging prefix already exists; inspect or clean the prior run")
    s3.upload_file(
        str(source),
        context.staging_bucket,
        key,
        # Rely on the bucket's customer-managed KMS default. Sending only the
        # generic aws:kms header would select the AWS-managed S3 key instead.
        ExtraArgs={
            "Tagging": f"MigrationId={migration_id}",
        },
    )
    return key


def start_import_task(
    context: StackContext,
    *,
    session: Any,
    plan: ImportPlan,
    migration_id: str,
    source_key: str,
    original_desired_count: int,
    recovery_points: tuple[RecoveryPoint, RecoveryPoint],
) -> ExecutionReceipt:
    """Launch exactly one dormant import task with explicit network placement."""

    source_sha = plan.checksums["source"].removeprefix("sha256:")
    command = [
        "--migration-id",
        migration_id,
        "--source-key",
        source_key,
        "--source-sha256",
        source_sha,
        "--source-fingerprint",
        plan.source_fingerprint,
        "--recovery-verified",
    ]
    ecs = _client(session.client, "ecs", context.region)
    response = ecs.run_task(
        cluster=context.cluster_name,
        taskDefinition=context.task_definition_arn,
        launchType="FARGATE",
        count=1,
        platformVersion="LATEST",
        startedBy=migration_id,
        clientToken=migration_id,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": list(context.private_subnet_ids),
                "securityGroups": [context.task_security_group_id],
                "assignPublicIp": "DISABLED",
            }
        },
        overrides={
            "containerOverrides": [
                {
                    "name": "openemr-import",
                    "command": command,
                }
            ]
        },
        tags=[
            {"key": "MigrationId", "value": migration_id},
            {"key": "Purpose", "value": "OpenEMRImport"},
        ],
        enableECSManagedTags=True,
        propagateTags="TASK_DEFINITION",
    )
    failures = response.get("failures", [])
    tasks = response.get("tasks", [])
    if failures or len(tasks) != 1 or not tasks[0].get("taskArn"):
        raise AwsImportError("ECS rejected the import task launch")
    return ExecutionReceipt(
        schema_version=1,
        migration_id=migration_id,
        account_id=context.account_id,
        region=context.region,
        stack_name=context.stack_name,
        cluster_name=context.cluster_name,
        service_name=context.service_name,
        service_url=context.service_url,
        openemr_version=context.openemr_version,
        original_desired_count=original_desired_count,
        task_arn=tasks[0]["taskArn"],
        task_definition_arn=context.task_definition_arn,
        staging_bucket=context.staging_bucket,
        source_key=source_key,
        started_at=datetime.now(UTC).isoformat(),
        recovery_point_arns=(
            recovery_points[0].recovery_point_arn,
            recovery_points[1].recovery_point_arn,
        ),
        recovery_point_dates=(
            recovery_points[0].creation_date,
            recovery_points[1].creation_date,
        ),
    )


def start_cleanup_task(
    context: StackContext,
    *,
    session: Any,
    migration_id: str,
) -> str:
    """Launch a scoped worker that removes one migration's EFS artifacts."""

    ecs = _client(session.client, "ecs", context.region)
    response = ecs.run_task(
        cluster=context.cluster_name,
        taskDefinition=context.task_definition_arn,
        launchType="FARGATE",
        count=1,
        platformVersion="LATEST",
        startedBy=f"{migration_id}-cleanup",
        clientToken=f"{migration_id}-cleanup",
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": list(context.private_subnet_ids),
                "securityGroups": [context.task_security_group_id],
                "assignPublicIp": "DISABLED",
            }
        },
        overrides={
            "containerOverrides": [
                {
                    "name": "openemr-import",
                    "command": [
                        "--operation",
                        "cleanup",
                        "--migration-id",
                        migration_id,
                        "--delete-site-backup",
                    ],
                }
            ]
        },
        tags=[
            {"key": "MigrationId", "value": migration_id},
            {"key": "Purpose", "value": "OpenEMRImportCleanup"},
        ],
        enableECSManagedTags=True,
        propagateTags="TASK_DEFINITION",
    )
    tasks = response.get("tasks", [])
    if response.get("failures") or len(tasks) != 1 or not tasks[0].get("taskArn"):
        raise AwsImportError("ECS rejected the import cleanup task launch")
    task_arn = tasks[0]["taskArn"]
    if not isinstance(task_arn, str):
        raise AwsImportError("ECS returned an invalid cleanup task ARN")
    return task_arn


def wait_for_task(
    context: StackContext,
    *,
    session: Any,
    task_arn: str,
    maximum_attempts: int = 240,
) -> int:
    """Wait for one task and return its sole container exit code."""

    ecs = _client(session.client, "ecs", context.region)
    waiter = ecs.get_waiter("tasks_stopped")
    waiter.wait(
        cluster=context.cluster_name,
        tasks=[task_arn],
        WaiterConfig={"Delay": 15, "MaxAttempts": maximum_attempts},
    )
    response = ecs.describe_tasks(
        cluster=context.cluster_name,
        tasks=[task_arn],
    )
    tasks = response.get("tasks", [])
    if len(tasks) != 1:
        raise AwsImportError("Unable to resolve completed ECS task")
    containers = tasks[0].get("containers", [])
    exit_code = containers[0].get("exitCode") if len(containers) == 1 else None
    if not isinstance(exit_code, int):
        raise AwsImportError("Completed ECS task did not publish an exit code")
    return exit_code


def read_remote_status(receipt: ExecutionReceipt, *, session: Any) -> dict[str, Any]:
    """Return bounded S3 worker status plus the current ECS task state."""

    s3 = _client(session.client, "s3", receipt.region)
    try:
        response = s3.get_object(
            Bucket=receipt.staging_bucket,
            Key=f"migrations/{receipt.migration_id}/status.json",
        )
        body = response["Body"].read(64 * 1024 + 1)
        if len(body) > 64 * 1024:
            raise AwsImportError("Worker status object exceeds the size limit")
        worker = json.loads(body)
        if (
            not isinstance(worker, dict)
            or worker.get("schema_version") != 1
            or worker.get("migration_id") != receipt.migration_id
            or worker.get("status") not in {"running", "failed", "succeeded"}
        ):
            raise AwsImportError("Worker status object is malformed")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in {
            "NoSuchKey",
            "404",
        }:
            raise
        worker = {"status": "not-yet-published", "phase": "pending"}
    ecs = _client(session.client, "ecs", receipt.region)
    response = ecs.describe_tasks(
        cluster=receipt.cluster_name,
        tasks=[receipt.task_arn],
    )
    tasks = response.get("tasks", [])
    task: dict[str, Any] = {}
    if len(tasks) == 1:
        item = tasks[0]
        containers = item.get("containers", [])
        task = {
            "last_status": item.get("lastStatus"),
            "stop_code": item.get("stopCode"),
            "container_exit_code": (containers[0].get("exitCode") if len(containers) == 1 else None),
        }
    service_response = ecs.describe_services(
        cluster=receipt.cluster_name,
        services=[receipt.service_name],
    )
    services = service_response.get("services", [])
    service: dict[str, Any] = {}
    if len(services) == 1:
        service = {
            "desired_count": services[0].get("desiredCount"),
            "running_count": services[0].get("runningCount"),
            "pending_count": services[0].get("pendingCount"),
        }
    scalable_target = _service_scalable_target(
        region=receipt.region,
        cluster_name=receipt.cluster_name,
        service_name=receipt.service_name,
        session=session,
    )
    suspension_states = _suspension_states(scalable_target)
    return {
        "schema_version": 1,
        "migration_id": receipt.migration_id,
        "worker": worker,
        "task": task,
        "service": service,
        "autoscaling": {
            "minimum_capacity": scalable_target["MinCapacity"],
            "maximum_capacity": scalable_target["MaxCapacity"],
            "active": not any(suspension_states.values()),
            "suspended": all(suspension_states.values()),
        },
    }


def cleanup_staging_scope(
    *,
    region: str,
    staging_bucket: str,
    migration_id: str,
    session: Any,
) -> int:
    """Delete all versions of only the migration-scoped S3 staging objects."""

    s3 = _client(session.client, "s3", region)
    prefix = f"migrations/{migration_id}/"
    objects: list[dict[str, str]] = []
    key_marker: str | None = None
    version_marker: str | None = None
    while True:
        arguments: dict[str, Any] = {
            "Bucket": staging_bucket,
            "Prefix": prefix,
            "MaxKeys": 1000,
        }
        if key_marker:
            arguments["KeyMarker"] = key_marker
        if version_marker:
            arguments["VersionIdMarker"] = version_marker
        response = s3.list_object_versions(**arguments)
        for collection in ("Versions", "DeleteMarkers"):
            objects.extend(
                {"Key": item["Key"], "VersionId": item["VersionId"]}
                for item in response.get(collection, [])
                if str(item.get("Key", "")).startswith(prefix) and item.get("VersionId")
            )
        if not response.get("IsTruncated"):
            break
        key_marker = response.get("NextKeyMarker")
        version_marker = response.get("NextVersionIdMarker")
        if not key_marker:
            raise AwsImportError("Malformed S3 pagination response")
    deleted = 0
    for offset in range(0, len(objects), 1000):
        batch = objects[offset : offset + 1000]
        deletion = s3.delete_objects(
            Bucket=staging_bucket,
            Delete={"Objects": batch, "Quiet": True},
        )
        if deletion.get("Errors"):
            raise AwsImportError("S3 reported a partial migration cleanup failure")
        deleted += len(batch)
    verification = s3.list_object_versions(
        Bucket=staging_bucket,
        Prefix=prefix,
        MaxKeys=1,
    )
    if verification.get("Versions") or verification.get("DeleteMarkers"):
        raise AwsImportError("Migration staging prefix is not empty after cleanup")
    return deleted


def cleanup_staging(
    receipt: ExecutionReceipt,
    *,
    session: Any,
) -> int:
    """Delete only the receipt's migration-scoped S3 staging objects."""

    return cleanup_staging_scope(
        region=receipt.region,
        staging_bucket=receipt.staging_bucket,
        migration_id=receipt.migration_id,
        session=session,
    )


def write_receipt(path: Path, receipt: ExecutionReceipt) -> None:
    """Persist non-secret state atomically with owner-only permissions."""

    ensure_owner_only_directory(
        path.parent,
        parents=True,
        label="OpenEMR import state",
    )
    atomic_write_json(path, asdict(receipt))


def read_receipt(path: Path) -> ExecutionReceipt:
    """Read and minimally validate a local execution receipt."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["recovery_point_arns"] = tuple(data["recovery_point_arns"])
        data["recovery_point_dates"] = tuple(data["recovery_point_dates"])
        receipt = ExecutionReceipt(**data)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise AwsImportError(f"Invalid execution receipt: {path}") from exc
    if receipt.schema_version != 1:
        raise AwsImportError("Unsupported execution receipt schema")
    if not re.fullmatch(r"import-[a-f0-9]{16}", receipt.migration_id):
        raise AwsImportError("Invalid migration identifier in execution receipt")
    return receipt
