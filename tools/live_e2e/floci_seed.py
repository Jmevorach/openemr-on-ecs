"""Seed a Floci emulator with the AWS surface exercised by live E2E preflight/cleanup."""

from __future__ import annotations

import json
import time
from typing import Any

import boto3
from botocore.exceptions import ClientError

DEFAULT_ACCOUNT_ID = "123456789012"
DEFAULT_REGION = "us-east-1"
DEFAULT_ROUTE53_DOMAIN = "e2e.floci.test"
DEFAULT_BOOTSTRAP_STACK = "CDKToolkit"
DEFAULT_QUALIFIER = "hnb659fds"
DEFAULT_OPERATOR_USER = "openemr-floci-e2e"


def boto_client(session: Any, service: str, *, endpoint_url: str, region: str) -> Any:
    """Create a Floci-targeted boto3 client."""

    return session.client(service, endpoint_url=endpoint_url, region_name=region)


def seed_live_e2e_world(
    session: Any,
    *,
    endpoint_url: str,
    account_id: str = DEFAULT_ACCOUNT_ID,
    region: str = DEFAULT_REGION,
    route53_domain: str = DEFAULT_ROUTE53_DOMAIN,
    bootstrap_stack_name: str = DEFAULT_BOOTSTRAP_STACK,
    qualifier: str = DEFAULT_QUALIFIER,
    operator_user: str = DEFAULT_OPERATOR_USER,
    include_bootstrap_fixture: bool = True,
) -> dict[str, str]:
    """Create bootstrap stack, hosted zone, and CDK roles required by adapter.preflight.

    Set ``include_bootstrap_fixture=False`` when a real ``cdk bootstrap`` will create
    the toolkit stack (Floci CDK deploy/destroy smoke).
    """

    cfn = boto_client(session, "cloudformation", endpoint_url=endpoint_url, region=region)
    route53 = boto_client(session, "route53", endpoint_url=endpoint_url, region=region)
    iam = boto_client(session, "iam", endpoint_url=endpoint_url, region=region)

    operator = _ensure_operator_user(iam, username=operator_user)
    hosted_zone_id = _ensure_hosted_zone(route53, route53_domain)
    role_names: list[str] = []
    if include_bootstrap_fixture:
        _ensure_bootstrap_stack(cfn, bootstrap_stack_name, qualifier=qualifier)
        role_names = _ensure_bootstrap_roles(
            iam,
            account_id=account_id,
            region=region,
            qualifier=qualifier,
        )
    return {
        "account_id": account_id,
        "region": region,
        "route53_domain": route53_domain,
        "hosted_zone_id": hosted_zone_id,
        "bootstrap_stack_name": bootstrap_stack_name,
        "qualifier": qualifier,
        "role_count": str(len(role_names)),
        "aws_access_key_id": operator["access_key_id"],
        "aws_secret_access_key": operator["secret_access_key"],
        "operator_user": operator_user,
    }


def seed_owned_stack(
    session: Any,
    *,
    endpoint_url: str,
    stack_name: str,
    run_id: str,
    region: str = DEFAULT_REGION,
    application_url: str = "https://openemr.e2e.floci.test/",
    wait_seconds: float = 30.0,
) -> str:
    """Create a minimal owned CloudFormation stack for cleanup/ownership tests."""

    cfn = boto_client(session, "cloudformation", endpoint_url=endpoint_url, region=region)
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Floci-backed live E2E ownership fixture",
        "Resources": {
            "OwnershipHandle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        },
        "Outputs": {
            "LiveE2ERunId": {"Value": run_id},
            "ApplicationURL": {"Value": application_url},
        },
    }
    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=["CAPABILITY_NAMED_IAM"],
        )
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in {"AlreadyExistsException", "ValidationError"}:
            raise
    deadline = time.monotonic() + wait_seconds
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    while str(stack.get("StackStatus", "")).endswith("_IN_PROGRESS") and time.monotonic() < deadline:
        time.sleep(0.2)
        stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return str(stack["StackId"])


def seed_service_smoke_resources(
    session: Any,
    *,
    endpoint_url: str,
    region: str = DEFAULT_REGION,
    bucket_name: str = "openemr-floci-smoke",
) -> dict[str, str]:
    """Create lightweight resources that exercise services used outside pure preflight."""

    s3 = boto_client(session, "s3", endpoint_url=endpoint_url, region=region)
    kms = boto_client(session, "kms", endpoint_url=endpoint_url, region=region)
    logs = boto_client(session, "logs", endpoint_url=endpoint_url, region=region)
    ecs = boto_client(session, "ecs", endpoint_url=endpoint_url, region=region)

    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            raise
    s3.put_object(Bucket=bucket_name, Key="smoke.txt", Body=b"floci")
    key = kms.create_key(Description="openemr-floci-smoke")["KeyMetadata"]["KeyId"]
    log_group = "/openemr/floci/smoke"
    try:
        logs.create_log_group(logGroupName=log_group)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in {"ResourceAlreadyExistsException"}:
            raise
    cluster = "openemr-floci-smoke"
    try:
        ecs.create_cluster(clusterName=cluster)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in {"ClusterAlreadyExistsException", "InvalidParameterException"}:
            raise
    return {
        "bucket_name": bucket_name,
        "kms_key_id": key,
        "log_group": log_group,
        "ecs_cluster": cluster,
    }


def _ensure_operator_user(iam: Any, *, username: str) -> dict[str, str]:
    """Create a non-root IAM user/access key so live E2E root rejection is satisfied."""

    try:
        iam.create_user(UserName=username)
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", ""))
        if code not in {"EntityAlreadyExists", "EntityAlreadyExistsException"}:
            raise
    allow_all = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName="floci-operator-allow-all",
            PolicyDocument=json.dumps(allow_all),
        )
    except ClientError as exc:
        # Some Floci builds reject inline user policies while still allowing API calls.
        code = str(exc.response.get("Error", {}).get("Code", ""))
        message = str(exc.response.get("Error", {}).get("Message", "")).lower()
        if code not in {"AccessDenied", "AccessDeniedException", "NotImplemented", "UnknownOperationException"} and (
            "not implemented" not in message and "unknown operation" not in message
        ):
            raise
    existing = iam.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
    for item in existing:
        key_id = item.get("AccessKeyId")
        if isinstance(key_id, str) and key_id:
            iam.delete_access_key(UserName=username, AccessKeyId=key_id)
    created = iam.create_access_key(UserName=username)["AccessKey"]
    return {
        "access_key_id": str(created["AccessKeyId"]),
        "secret_access_key": str(created["SecretAccessKey"]),
    }


def operator_session(
    *,
    endpoint_url: str,
    region: str,
    access_key_id: str,
    secret_access_key: str,
) -> Any:
    """Build a boto3 session using the seeded non-root Floci operator credentials."""

    del endpoint_url  # callers still pass it for API symmetry with other helpers
    return boto3.Session(
        region_name=region,
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
    )


def _normalize_hosted_zone_id(zone_id: str) -> str:
    value = zone_id.removeprefix("/hostedzone/").upper()
    if value and not value.startswith("Z"):
        value = f"Z{value}"
    return value


def _ensure_hosted_zone(route53: Any, domain: str) -> str:
    normalized = domain.rstrip(".").lower()
    existing = route53.list_hosted_zones_by_name(DNSName=normalized, MaxItems="5").get("HostedZones", [])
    matches = [zone for zone in existing if str(zone.get("Name", "")).rstrip(".").lower() == normalized]
    if matches:
        return _normalize_hosted_zone_id(str(matches[0]["Id"]))
    created = route53.create_hosted_zone(
        Name=normalized,
        CallerReference=f"openemr-floci-{normalized}",
        HostedZoneConfig={"Comment": "openemr live e2e floci fixture", "PrivateZone": False},
    )
    return _normalize_hosted_zone_id(str(created["HostedZone"]["Id"]))


def _ensure_bootstrap_stack(cfn: Any, stack_name: str, *, qualifier: str) -> None:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Floci CDK bootstrap fixture",
        "Parameters": {
            "Qualifier": {
                "Type": "String",
                "Default": qualifier,
            }
        },
        "Resources": {
            "BootstrapMarker": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        },
        "Outputs": {
            "BootstrapVersion": {
                "Value": "21",
                "Description": "Minimum CDK bootstrap version accepted by live E2E",
            }
        },
    }
    try:
        cfn.describe_stacks(StackName=stack_name)
        return
    except ClientError as exc:
        message = str(exc.response.get("Error", {}).get("Message", ""))
        if "does not exist" not in message:
            raise
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": "Qualifier", "ParameterValue": qualifier}],
    )


def _ensure_bootstrap_roles(
    iam: Any,
    *,
    account_id: str,
    region: str,
    qualifier: str,
) -> list[str]:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    allow_all = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    purposes = ("deploy", "file-publishing", "image-publishing", "lookup", "cfn-exec")
    created: list[str] = []
    for purpose in purposes:
        if purpose == "cfn-exec":
            role_name = f"cdk-{qualifier}-cfn-exec-role-{account_id}-{region}"
        else:
            role_name = f"cdk-{qualifier}-{purpose}-role-{account_id}-{region}"
        try:
            iam.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust),
                Description=f"Floci fixture role for {purpose}",
            )
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in {"EntityAlreadyExists", "EntityAlreadyExistsException"}:
                raise
        try:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="floci-allow-all",
                PolicyDocument=json.dumps(allow_all),
            )
        except ClientError as exc:
            # Some emulator builds accept create_role but reject inline policies; assume_role still works.
            code = str(exc.response.get("Error", {}).get("Code", ""))
            message = str(exc.response.get("Error", {}).get("Message", "")).lower()
            if code not in {
                "AccessDenied",
                "AccessDeniedException",
                "NotImplemented",
                "UnknownOperationException",
            } and ("not implemented" not in message and "unknown operation" not in message):
                raise
        created.append(role_name)
    return created
