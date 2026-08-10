#!/usr/bin/env python3
"""Minimal CDK application for Floci bootstrap/deploy/destroy smoke tests.

This is intentionally not the OpenEMR production stack. It only creates
emulator-friendly resources so CI can prove the repository's pinned CDK CLI
can publish a cloud assembly to Floci and tear it down.
"""

from __future__ import annotations

from typing import Any

import aws_cdk as cdk
from aws_cdk import (
    CfnOutput,
    RemovalPolicy,
    Stack,
)
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs as logs
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_sqs as sqs
from aws_cdk import aws_ssm as ssm
from constructs import Construct


class FlociSmokeStack(Stack):
    """Small, disposable stack that exercises common AWS service surfaces."""

    def __init__(self, scope: Construct, construct_id: str, **kwargs: Any) -> None:
        super().__init__(scope, construct_id, **kwargs)

        bucket = s3.Bucket(
            self,
            "FlociSmokeBucket",
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=False,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
        )
        queue = sqs.Queue(
            self,
            "FlociSmokeQueue",
            removal_policy=RemovalPolicy.DESTROY,
            retention_period=cdk.Duration.days(1),
        )
        parameter = ssm.StringParameter(
            self,
            "FlociSmokeParameter",
            parameter_name="/openemr/floci/smoke",
            string_value="floci-cdk-smoke",
            simple_name=False,
        )
        log_group = logs.LogGroup(
            self,
            "FlociSmokeLogs",
            removal_policy=RemovalPolicy.DESTROY,
            retention=logs.RetentionDays.ONE_DAY,
        )
        role = iam.Role(
            self,
            "FlociSmokeRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Floci CDK smoke role",
        )
        bucket.grant_read_write(role)
        queue.grant_send_messages(role)

        CfnOutput(self, "BucketName", value=bucket.bucket_name)
        CfnOutput(self, "QueueUrl", value=queue.queue_url)
        CfnOutput(self, "ParameterName", value=parameter.parameter_name)
        CfnOutput(self, "LogGroupName", value=log_group.log_group_name)
        CfnOutput(self, "RoleArn", value=role.role_arn)


def main() -> None:
    app = cdk.App()
    account = app.node.try_get_context("account") or "123456789012"
    region = app.node.try_get_context("region") or "us-east-1"
    FlociSmokeStack(
        app,
        "OpenemrFlociSmoke",
        env=cdk.Environment(account=str(account), region=str(region)),
        description="Floci CDK deploy/destroy smoke stack for openemr-on-ecs CI",
    )
    app.synth()


if __name__ == "__main__":
    main()
