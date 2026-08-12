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

import requests  # type: ignore[import-untyped]
from botocore.exceptions import ClientError

from tools._shared import (
    ToolError,
    atomic_write_private_json,
    ensure_owner_only_directory,
    read_private_json,
)

from .models import ImportPlan


class AwsImportError(RuntimeError):
    """Raised when an AWS-side import safeguard or operation fails."""


class ImportLockOutcomeUnknown(AwsImportError):
    """Raised when S3 may have created a lock but did not return its identity."""


@dataclass(frozen=True)
class StackContext:
    """Deployment details resolved from one explicit CloudFormation stack."""

    account_id: str
    region: str
    stack_name: str
    stack_creation_time: str
    stack_last_updated_time: str | None
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
    database_security_group_id: str = ""
    efs_security_group_id: str = ""
    efs_access_point_id: str = ""


@dataclass(frozen=True)
class RecoveryPoint:
    """A recent completed AWS Backup recovery point."""

    resource_arn: str
    recovery_point_arn: str
    creation_date: str


@dataclass(frozen=True)
class ImportLock:
    """Immutable identity of the conditionally-created stack-wide lock."""

    bucket: str
    key: str
    migration_id: str
    etag: str
    version_id: str | None


@dataclass(frozen=True)
class ExecutionReceipt:
    """Minimal non-secret execution state persisted locally."""

    schema_version: int
    migration_id: str
    account_id: str
    region: str
    stack_name: str
    stack_creation_time: str
    stack_last_updated_time: str | None
    cluster_name: str
    service_name: str
    service_url: str
    openemr_version: str
    original_desired_count: int
    task_arn: str
    task_definition_arn: str
    staging_bucket: str
    staging_kms_key_arn: str
    task_security_group_id: str
    private_subnet_ids: tuple[str, ...]
    database_arn: str
    efs_arn: str
    source_key: str
    started_at: str
    recovery_point_arns: tuple[str, str]
    recovery_point_dates: tuple[str, str]
    lock_etag: str
    lock_version_id: str | None


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
    "OpenEMRImportDatabaseSecurityGroupId",
    "OpenEMRImportEfsSecurityGroupId",
    "OpenEMRImportEfsAccessPointId",
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
    creation_time = stack.get("CreationTime")
    last_updated_time = stack.get("LastUpdatedTime")
    if not isinstance(creation_time, datetime) or (
        last_updated_time is not None and not isinstance(last_updated_time, datetime)
    ):
        raise AwsImportError("Stack lifecycle timestamps are missing or invalid")
    outputs = {
        item["OutputKey"]: item["OutputValue"]
        for item in stack.get("Outputs", [])
        if item.get("OutputKey") and item.get("OutputValue")
    }
    missing = sorted(REQUIRED_OUTPUTS - outputs.keys())
    if missing:
        raise AwsImportError("Stack predates import support or is incomplete; missing outputs: " + ", ".join(missing))
    if outputs["OpenEMRImportTargetMode"] != "fresh-target-only":
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
    security_group_outputs = (
        outputs["OpenEMRImportSecurityGroupId"],
        outputs["OpenEMRImportDatabaseSecurityGroupId"],
        outputs["OpenEMRImportEfsSecurityGroupId"],
    )
    if any(not re.fullmatch(r"sg-[0-9a-f]+", value) for value in security_group_outputs):
        raise AwsImportError("Invalid import security-group output")
    efs_access_point_id = outputs["OpenEMRImportEfsAccessPointId"]
    if not re.fullmatch(r"fsap-[0-9a-f]+", efs_access_point_id):
        raise AwsImportError("Invalid import EFS access-point output")
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
        stack_creation_time=creation_time.astimezone(UTC).isoformat(),
        stack_last_updated_time=(
            last_updated_time.astimezone(UTC).isoformat() if isinstance(last_updated_time, datetime) else None
        ),
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
        database_security_group_id=outputs["OpenEMRImportDatabaseSecurityGroupId"],
        efs_security_group_id=outputs["OpenEMRImportEfsSecurityGroupId"],
        efs_access_point_id=efs_access_point_id,
    )


def assert_new_import_target(
    context: StackContext,
    *,
    maximum_age_hours: int = 24,
    now: datetime | None = None,
) -> None:
    """Require an import-target stack created once and used promptly."""

    if context.import_target_mode != "fresh-target-only":
        raise AwsImportError("Stack is not marked as a fresh import target")
    if context.stack_last_updated_time is not None:
        raise AwsImportError("Fresh import target must not have any stack updates")
    try:
        created = datetime.fromisoformat(context.stack_creation_time)
    except ValueError as exc:
        raise AwsImportError("Fresh import target creation time is invalid") from exc
    if created.tzinfo is None:
        raise AwsImportError("Fresh import target creation time lacks a timezone")
    age = (now or datetime.now(UTC)) - created.astimezone(UTC)
    if age < timedelta(0) or age > timedelta(hours=maximum_age_hours):
        raise AwsImportError(f"Fresh import target must be less than {maximum_age_hours} hours old")


def assert_import_resource_bindings(
    context: StackContext,
    *,
    session: Any,
) -> None:
    """Verify that import outputs still describe one private, encrypted graph."""

    s3 = _client(session.client, "s3", context.region)
    s3.head_bucket(
        Bucket=context.staging_bucket,
        ExpectedBucketOwner=context.account_id,
    )
    encryption = s3.get_bucket_encryption(
        Bucket=context.staging_bucket,
        ExpectedBucketOwner=context.account_id,
    )
    defaults = [
        item.get("ApplyServerSideEncryptionByDefault", {})
        for item in encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
    ]
    if (
        len(defaults) != 1
        or defaults[0].get("SSEAlgorithm") != "aws:kms"
        or defaults[0].get("KMSMasterKeyID") != context.staging_kms_key_arn
    ):
        raise AwsImportError("Import staging bucket is not bound to the expected KMS key")

    key = (
        _client(session.client, "kms", context.region)
        .describe_key(KeyId=context.staging_kms_key_arn)
        .get("KeyMetadata", {})
    )
    if (
        key.get("Arn") != context.staging_kms_key_arn
        or key.get("Enabled") is not True
        or key.get("KeyManager") != "CUSTOMER"
        or key.get("KeyUsage") != "ENCRYPT_DECRYPT"
    ):
        raise AwsImportError("Import staging KMS key is not enabled and customer managed")

    database_identifier = context.database_arn.rsplit(":", 1)[-1]
    clusters = (
        _client(session.client, "rds", context.region)
        .describe_db_clusters(DBClusterIdentifier=database_identifier)
        .get("DBClusters", [])
    )
    if (
        len(clusters) != 1
        or clusters[0].get("DBClusterArn") != context.database_arn
        or clusters[0].get("Status") != "available"
    ):
        raise AwsImportError("Import database output is not the available target cluster")

    file_system_id = context.efs_arn.rsplit("/", 1)[-1]
    efs_client = _client(session.client, "efs", context.region)
    file_systems = efs_client.describe_file_systems(FileSystemId=file_system_id).get("FileSystems", [])
    access_points = efs_client.describe_access_points(AccessPointId=context.efs_access_point_id).get("AccessPoints", [])
    if (
        len(file_systems) != 1
        or file_systems[0].get("FileSystemArn") != context.efs_arn
        or file_systems[0].get("Encrypted") is not True
        or file_systems[0].get("LifeCycleState") != "available"
    ):
        raise AwsImportError("Import EFS output is not the available encrypted target")
    if (
        len(access_points) != 1
        or access_points[0].get("AccessPointId") != context.efs_access_point_id
        or access_points[0].get("FileSystemId") != file_system_id
        or access_points[0].get("LifeCycleState") != "available"
        or access_points[0].get("PosixUser", {}).get("Uid") != "0"
        or access_points[0].get("PosixUser", {}).get("Gid") != "101"
        or access_points[0].get("RootDirectory", {}).get("Path") != "/"
    ):
        raise AwsImportError("Import EFS access point is not bound to the expected filesystem identity")

    ec2 = _client(session.client, "ec2", context.region)
    subnets = ec2.describe_subnets(
        SubnetIds=list(context.private_subnet_ids),
    ).get("Subnets", [])
    security_groups = ec2.describe_security_groups(
        GroupIds=[
            context.task_security_group_id,
            context.database_security_group_id,
            context.efs_security_group_id,
        ],
    ).get("SecurityGroups", [])
    security_groups_by_id = {str(item.get("GroupId", "")): item for item in security_groups}
    task_security_group = security_groups_by_id.get(
        context.task_security_group_id,
        {},
    )
    egress = task_security_group.get("IpPermissionsEgress", [])
    expected_egress_ports = {443, 2049, 3306}
    egress_ports = {
        item.get("FromPort")
        for item in egress
        if item.get("IpProtocol") == "tcp" and item.get("FromPort") == item.get("ToPort")
    }
    https_egress = [item for item in egress if item.get("FromPort") == 443]
    private_egress = [item for item in egress if item.get("FromPort") in {2049, 3306}]
    vpc_ids = {str(item.get("VpcId", "")) for item in [*subnets, *security_groups] if item.get("VpcId")}
    expected_private_targets = {
        2049: context.efs_security_group_id,
        3306: context.database_security_group_id,
    }
    if (
        len(subnets) != len(context.private_subnet_ids)
        or any(item.get("MapPublicIpOnLaunch") is not False for item in subnets)
        or len(security_groups_by_id) != 3
        or len(vpc_ids) != 1
        or task_security_group.get("IpPermissions")
        or len(egress) != 3
        or egress_ports != expected_egress_ports
        or len(https_egress) != 1
        or len(https_egress[0].get("IpRanges", [])) != 1
        or https_egress[0]["IpRanges"][0].get("CidrIp") != "0.0.0.0/0"
        or https_egress[0].get("Ipv6Ranges")
        or any(
            len(item.get("UserIdGroupPairs", [])) != 1
            or item["UserIdGroupPairs"][0].get("GroupId") != expected_private_targets.get(item.get("FromPort"))
            or item.get("IpRanges")
            or item.get("Ipv6Ranges")
            for item in private_egress
        )
    ):
        raise AwsImportError("Import task network outputs are not least-privilege private networking")

    task = (
        _client(session.client, "ecs", context.region)
        .describe_task_definition(
            taskDefinition=context.task_definition_arn,
        )
        .get("taskDefinition", {})
    )
    containers = task.get("containerDefinitions", [])
    environments = (
        {str(item.get("name", "")): str(item.get("value", "")) for item in containers[0].get("environment", [])}
        if len(containers) == 1
        else {}
    )
    efs_volumes = [
        item.get("efsVolumeConfiguration", {}) for item in task.get("volumes", []) if item.get("efsVolumeConfiguration")
    ]
    if (
        task.get("taskDefinitionArn") != context.task_definition_arn
        or task.get("networkMode") != "awsvpc"
        or "FARGATE" not in task.get("requiresCompatibilities", [])
        or task.get("runtimePlatform", {}).get("cpuArchitecture") != "ARM64"
        or len(containers) != 1
        or containers[0].get("name") != "openemr-import"
        or environments.get("IMPORT_STAGING_BUCKET_OWNER") != context.account_id
        or environments.get("IMPORT_STAGING_KMS_KEY_ARN") != context.staging_kms_key_arn
        or len(efs_volumes) != 1
        or efs_volumes[0].get("fileSystemId") != file_system_id
        or efs_volumes[0].get("transitEncryption") != "ENABLED"
        or efs_volumes[0].get("authorizationConfig", {}).get("iam") != "ENABLED"
        or efs_volumes[0].get("authorizationConfig", {}).get("accessPointId") != context.efs_access_point_id
    ):
        raise AwsImportError("Import task definition is not bound to the expected private resources")


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
        or service.get("pendingCount") != 0
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
    last_error = "no successful HTTP response"
    for attempt in range(attempts):
        try:
            response = requests.get(
                target,
                headers={"User-Agent": "openemr-on-ecs-import-health/1"},
                timeout=20,
                allow_redirects=False,
            )
            body = getattr(response, "text", "")
            if response.status_code == 200 and isinstance(body, str) and "openemr" in body[:200_000].lower():
                return
            last_error = f"HTTP {response.status_code} without OpenEMR login markers"
        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        if attempt + 1 < attempts:
            sleep(15)
    raise AwsImportError(f"OpenEMR login page did not become healthy after import ({last_error})")


def recent_recovery_points(
    context: StackContext,
    *,
    session: Any,
    maximum_age_hours: int = 36,
    now: datetime | None = None,
) -> tuple[RecoveryPoint, RecoveryPoint]:
    """Require recent completed recovery points for Aurora and EFS."""

    backup = _client(session.client, "backup", context.region)
    try:
        stack_created = datetime.fromisoformat(context.stack_creation_time).astimezone(UTC)
    except (ValueError, TypeError) as exc:
        raise AwsImportError("Stack creation time is invalid") from exc
    threshold = max(
        (now or datetime.now(UTC)) - timedelta(hours=maximum_age_hours),
        stack_created,
    )
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
) -> ImportLock:
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
        response = s3.put_object(
            Bucket=context.staging_bucket,
            Key=IMPORT_LOCK_KEY,
            Body=payload,
            ContentType="application/json",
            Metadata={"migration-id": migration_id},
            IfNoneMatch="*",
            ExpectedBucketOwner=context.account_id,
            ServerSideEncryption="aws:kms",
            SSEKMSKeyId=context.staging_kms_key_arn,
        )
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in {"ConditionalRequestConflict", "PreconditionFailed"} or status in {409, 412}:
            raise AwsImportError("Another import already holds the stack-wide lock") from exc
        if (isinstance(status, int) and 500 <= status <= 599) or code in {
            "InternalError",
            "RequestTimeout",
            "RequestTimeoutException",
            "ServiceUnavailable",
            "SlowDown",
        }:
            raise ImportLockOutcomeUnknown("S3 import-lock write outcome is unknown") from exc
        raise
    etag = response.get("ETag")
    version_id = response.get("VersionId")
    if not isinstance(etag, str) or not etag:
        raise ImportLockOutcomeUnknown("S3 did not return an identity for the import lock")
    return ImportLock(
        bucket=context.staging_bucket,
        key=IMPORT_LOCK_KEY,
        migration_id=migration_id,
        etag=etag,
        version_id=version_id if isinstance(version_id, str) else None,
    )


def release_import_lock(
    context: StackContext,
    *,
    session: Any,
    lock: ImportLock,
) -> None:
    """Release only the stack-wide lock owned by this migration."""

    if lock.bucket != context.staging_bucket or lock.key != IMPORT_LOCK_KEY:
        raise AwsImportError("Import lock is not bound to the selected stack")
    s3 = _client(session.client, "s3", context.region)
    arguments: dict[str, Any] = {
        "Bucket": lock.bucket,
        "Key": lock.key,
        "ExpectedBucketOwner": context.account_id,
        "IfMatch": lock.etag,
    }
    try:
        s3.delete_object(**arguments)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        if code in {"NoSuchKey", "NotFound", "404"} or status == 404:
            return
        if code in {
            "ConditionalRequestConflict",
            "PreconditionFailed",
        } or status in {409, 412}:
            try:
                s3.head_object(
                    Bucket=lock.bucket,
                    Key=lock.key,
                    ExpectedBucketOwner=context.account_id,
                )
            except ClientError as head_exc:
                head_code = str(head_exc.response.get("Error", {}).get("Code", ""))
                head_status = head_exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                if head_code in {"NoSuchKey", "NotFound", "404"} or head_status == 404:
                    return
                raise
            raise AwsImportError("Import lock ownership changed during release; lock was not deleted") from exc
        raise


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
        ExpectedBucketOwner=context.account_id,
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
            "ExpectedBucketOwner": context.account_id,
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": context.staging_kms_key_arn,
            "Tagging": (f"MigrationId={migration_id}&DataClass=ImportSource"),
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
    lock: ImportLock,
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
        "--source-openemr-version",
        plan.source_openemr_version,
        "--source-database-version",
        str(plan.source_database_version),
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
        schema_version=4,
        migration_id=migration_id,
        account_id=context.account_id,
        region=context.region,
        stack_name=context.stack_name,
        stack_creation_time=context.stack_creation_time,
        stack_last_updated_time=context.stack_last_updated_time,
        cluster_name=context.cluster_name,
        service_name=context.service_name,
        service_url=context.service_url,
        openemr_version=context.openemr_version,
        original_desired_count=original_desired_count,
        task_arn=tasks[0]["taskArn"],
        task_definition_arn=context.task_definition_arn,
        staging_bucket=context.staging_bucket,
        staging_kms_key_arn=context.staging_kms_key_arn,
        task_security_group_id=context.task_security_group_id,
        private_subnet_ids=context.private_subnet_ids,
        database_arn=context.database_arn,
        efs_arn=context.efs_arn,
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
        lock_etag=lock.etag,
        lock_version_id=lock.version_id,
    )


def find_import_tasks(
    context: StackContext,
    *,
    session: Any,
    migration_id: str,
) -> tuple[dict[str, Any], ...]:
    """Find at most one task for an idempotent launch after client uncertainty."""

    ecs = _client(session.client, "ecs", context.region)
    candidate_arns: set[str] = set()
    for desired_status in ("RUNNING", "STOPPED"):
        token: str | None = None
        pages = 0
        while True:
            arguments: dict[str, Any] = {
                "cluster": context.cluster_name,
                "desiredStatus": desired_status,
                "maxResults": 100,
            }
            if token is not None:
                arguments["nextToken"] = token
            response = ecs.list_tasks(**arguments)
            candidate_arns.update(arn for arn in response.get("taskArns", []) if isinstance(arn, str) and arn)
            pages += 1
            if pages > 10 or len(candidate_arns) > 1000:
                raise AwsImportError("ECS task reconciliation exceeded its bounded cluster scan")
            next_token = response.get("nextToken")
            if not next_token:
                break
            if not isinstance(next_token, str):
                raise AwsImportError("ECS task reconciliation pagination is malformed")
            token = next_token
    if not candidate_arns:
        return ()
    matches: list[dict[str, Any]] = []
    sorted_candidates = sorted(candidate_arns)
    for offset in range(0, len(sorted_candidates), 100):
        batch = sorted_candidates[offset : offset + 100]
        response = ecs.describe_tasks(
            cluster=context.cluster_name,
            tasks=batch,
        )
        if response.get("failures"):
            raise AwsImportError("Unable to reconcile the uncertain ECS task launch")
        for task in response.get("tasks", []):
            if not isinstance(task, dict):
                raise AwsImportError("ECS task reconciliation returned malformed task data")
            if (
                task.get("taskArn") in candidate_arns
                and task.get("taskDefinitionArn") == context.task_definition_arn
                and task.get("startedBy") == migration_id
            ):
                matches.append(task)
                if len(matches) > 1:
                    raise AwsImportError("More than one ECS task exists for the migration identifier")
    return tuple(matches)


def start_cleanup_task(
    context: StackContext,
    *,
    session: Any,
    migration_id: str,
    attempt: int = 1,
) -> str:
    """Launch a scoped worker that removes one migration's EFS artifacts."""

    ecs = _client(session.client, "ecs", context.region)
    if attempt < 1:
        raise ValueError("Cleanup attempt must be positive")
    cleanup_identity = f"{migration_id}-cleanup-{attempt}"
    response = ecs.run_task(
        cluster=context.cluster_name,
        taskDefinition=context.task_definition_arn,
        launchType="FARGATE",
        count=1,
        platformVersion="LATEST",
        startedBy=cleanup_identity,
        clientToken=cleanup_identity,
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


def start_recovery_task(
    context: StackContext,
    *,
    session: Any,
    migration_id: str,
    attempt: int,
) -> str:
    """Launch an idempotent task that restores the worker-created local baseline."""

    if attempt < 1:
        raise ValueError("Recovery attempt must be positive")
    recovery_identity = f"{migration_id}-recovery-{attempt}"
    ecs = _client(session.client, "ecs", context.region)
    response = ecs.run_task(
        cluster=context.cluster_name,
        taskDefinition=context.task_definition_arn,
        launchType="FARGATE",
        count=1,
        platformVersion="LATEST",
        startedBy=recovery_identity,
        clientToken=recovery_identity,
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
                        "recover",
                        "--migration-id",
                        migration_id,
                    ],
                }
            ]
        },
        tags=[
            {"key": "MigrationId", "value": migration_id},
            {"key": "Purpose", "value": "OpenEMRImportRecovery"},
        ],
        enableECSManagedTags=True,
        propagateTags="TASK_DEFINITION",
    )
    tasks = response.get("tasks", [])
    if response.get("failures") or len(tasks) != 1 or not tasks[0].get("taskArn"):
        raise AwsImportError("ECS rejected the import recovery task launch")
    task_arn = tasks[0]["taskArn"]
    if not isinstance(task_arn, str):
        raise AwsImportError("ECS returned an invalid recovery task ARN")
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
            ExpectedBucketOwner=receipt.account_id,
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
        container = containers[0] if len(containers) == 1 else {}
        task = {
            "last_status": item.get("lastStatus"),
            "stop_code": item.get("stopCode"),
            "container_exit_code": container.get("exitCode"),
            "identity_verified": (
                item.get("taskArn") == receipt.task_arn
                and item.get("taskDefinitionArn") == receipt.task_definition_arn
                and item.get("startedBy") == receipt.migration_id
                and container.get("name") == "openemr-import"
            ),
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
    expected_bucket_owner: str,
    session: Any,
) -> int:
    """Delete all versions of only the migration-scoped S3 staging objects."""

    s3 = _client(session.client, "s3", region)
    prefix = f"migrations/{migration_id}/"
    upload_key_marker: str | None = None
    upload_id_marker: str | None = None
    while True:
        upload_arguments: dict[str, Any] = {
            "Bucket": staging_bucket,
            "Prefix": prefix,
            "MaxUploads": 1000,
            "ExpectedBucketOwner": expected_bucket_owner,
        }
        if upload_key_marker:
            upload_arguments["KeyMarker"] = upload_key_marker
        if upload_id_marker:
            upload_arguments["UploadIdMarker"] = upload_id_marker
        uploads = s3.list_multipart_uploads(**upload_arguments)
        for upload in uploads.get("Uploads", []):
            key = upload.get("Key")
            upload_id = upload.get("UploadId")
            if isinstance(key, str) and key.startswith(prefix) and isinstance(upload_id, str):
                s3.abort_multipart_upload(
                    Bucket=staging_bucket,
                    Key=key,
                    UploadId=upload_id,
                    ExpectedBucketOwner=expected_bucket_owner,
                )
        if not uploads.get("IsTruncated"):
            break
        upload_key_marker = uploads.get("NextKeyMarker")
        upload_id_marker = uploads.get("NextUploadIdMarker")
        if not isinstance(upload_key_marker, str) or not isinstance(upload_id_marker, str):
            raise AwsImportError("Malformed S3 multipart-upload pagination response")

    objects: list[dict[str, str]] = []
    key_marker: str | None = None
    version_marker: str | None = None
    while True:
        arguments: dict[str, Any] = {
            "Bucket": staging_bucket,
            "Prefix": prefix,
            "MaxKeys": 1000,
            "ExpectedBucketOwner": expected_bucket_owner,
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
            ExpectedBucketOwner=expected_bucket_owner,
        )
        if deletion.get("Errors"):
            raise AwsImportError("S3 reported a partial migration cleanup failure")
        deleted += len(batch)
    verification = s3.list_object_versions(
        Bucket=staging_bucket,
        Prefix=prefix,
        MaxKeys=1,
        ExpectedBucketOwner=expected_bucket_owner,
    )
    if verification.get("Versions") or verification.get("DeleteMarkers"):
        raise AwsImportError("Migration staging prefix is not empty after cleanup")
    multipart_verification = s3.list_multipart_uploads(
        Bucket=staging_bucket,
        Prefix=prefix,
        MaxUploads=1,
        ExpectedBucketOwner=expected_bucket_owner,
    )
    if multipart_verification.get("Uploads"):
        raise AwsImportError("Migration staging prefix retains multipart uploads after cleanup")
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
        expected_bucket_owner=receipt.account_id,
        session=session,
    )


def write_receipt(path: Path, receipt: ExecutionReceipt) -> None:
    """Persist non-secret state atomically with owner-only permissions."""

    ensure_owner_only_directory(
        path.parent,
        parents=True,
        label="OpenEMR import state",
    )
    atomic_write_private_json(path, asdict(receipt), label="OpenEMR import state")


def read_receipt(path: Path) -> ExecutionReceipt:
    """Read and minimally validate a local execution receipt."""

    try:
        data = read_private_json(path, label="OpenEMR import state")
        if not isinstance(data, dict):
            raise TypeError("execution receipt must be a JSON object")
        cleanup_status = data.pop("cleanup_status", None)
        if cleanup_status not in {None, "in-progress", "failed"}:
            raise TypeError("invalid cleanup status")
        cleanup_attempt = data.pop("cleanup_attempt", 0)
        if isinstance(cleanup_attempt, bool) or not isinstance(cleanup_attempt, int) or cleanup_attempt < 0:
            raise TypeError("invalid cleanup attempt")
        abort_status = data.pop("abort_status", None)
        if abort_status not in {
            None,
            "service-restored",
            "cleanup-in-progress",
            "cleanup-failed",
        }:
            raise TypeError("invalid abort status")
        abort_cleanup_attempt = data.pop("abort_cleanup_attempt", 0)
        if (
            isinstance(abort_cleanup_attempt, bool)
            or not isinstance(abort_cleanup_attempt, int)
            or abort_cleanup_attempt < 0
        ):
            raise TypeError("invalid abort cleanup attempt")
        recovery_status = data.pop("recovery_status", None)
        if recovery_status not in {None, "in-progress", "failed", "complete"}:
            raise TypeError("invalid recovery status")
        recovery_attempt = data.pop("recovery_attempt", 0)
        if isinstance(recovery_attempt, bool) or not isinstance(recovery_attempt, int) or recovery_attempt < 0:
            raise TypeError("invalid recovery attempt")
        data["private_subnet_ids"] = tuple(data["private_subnet_ids"])
        data["recovery_point_arns"] = tuple(data["recovery_point_arns"])
        data["recovery_point_dates"] = tuple(data["recovery_point_dates"])
        receipt = ExecutionReceipt(**data)
    except (OSError, ToolError, AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AwsImportError(f"Invalid execution receipt: {path}") from exc
    if receipt.schema_version != 4:
        raise AwsImportError("Unsupported execution receipt schema")
    if not re.fullmatch(r"import-[a-f0-9]{16}", receipt.migration_id):
        raise AwsImportError("Invalid migration identifier in execution receipt")
    if not receipt.lock_etag:
        raise AwsImportError("Invalid import lock identity in execution receipt")
    return receipt
