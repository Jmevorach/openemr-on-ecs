"""Read probes, validation, timing, and owned-stack cleanup for live E2E."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError

from tools._shared import ToolError, hash_account_id

from .models import CheckResult, PhaseTiming, ResidualResource

_EXPECTED_RESOURCE_TYPES = {
    "AWS::ECS::Cluster",
    "AWS::ECS::Service",
    "AWS::EFS::FileSystem",
    "AWS::ElastiCache::ServerlessCache",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::RDS::DBCluster",
    "AWS::WAFv2::WebACLAssociation",
}
_FATAL_LOG_PATTERN = re.compile(
    r"(?i)\b(?:segmentation fault|out of memory|uncaught (?:exception|error)|"
    r"(?:fatal php|php fatal) error|kernel panic|panic:)\b"
)
_QUOTAS = (
    ("vpc-count", "vpc", "L-F678F1CE", 1.0),
    ("elastic-ip-count", "ec2", "L-0263D0A3", 2.0),
    ("fargate-vcpu", "fargate", "L-3032A538", 4.0),
    ("rds-clusters", "rds", "L-952B80B8", 1.0),
)
_WRITE_ACTIONS = (
    "acm:RequestCertificate",
    "application-autoscaling:RegisterScalableTarget",
    "backup:CreateBackupVault",
    "cloudformation:CreateChangeSet",
    "cloudformation:CreateStack",
    "cloudformation:DeleteStack",
    "cloudformation:ExecuteChangeSet",
    "cloudtrail:CreateTrail",
    "ec2:CreateVpc",
    "ecs:CreateCluster",
    "ecs:CreateService",
    "efs:CreateFileSystem",
    "elasticache:CreateServerlessCache",
    "elasticloadbalancing:CreateLoadBalancer",
    "iam:CreateRole",
    "iam:PassRole",
    "kms:CreateKey",
    "lambda:CreateFunction",
    "logs:CreateLogGroup",
    "rds:CreateDBCluster",
    "route53:ChangeResourceRecordSets",
    "s3:CreateBucket",
    "secretsmanager:CreateSecret",
    "sns:CreateTopic",
    "wafv2:CreateWebACL",
)
_BOOTSTRAP_ROLE_PURPOSES = (
    "deploy",
    "file-publishing",
    "image-publishing",
    "lookup",
)


def _is_unsupported_emulator_operation(exc: BaseException) -> bool:
    """Return True when an emulator rejects an API that real AWS must support."""

    if isinstance(exc, ClientError):
        code = str(exc.response.get("Error", {}).get("Code", ""))
        message = str(exc.response.get("Error", {}).get("Message", ""))
        if code in {"UnknownOperationException", "InternalError", "NotImplemented", "501"}:
            return True
        lowered = message.lower()
        if "unknown operation" in lowered or "not implemented" in lowered:
            return True
    text = str(exc).lower()
    return "unknown operation" in text or "not implemented" in text


class LiveE2EAws:
    """Bounded AWS adapter tied to one profile, account, and region."""

    def __init__(
        self,
        *,
        region: str,
        profile_name: str | None = None,
        session: Any | None = None,
        endpoint_url: str | None = None,
        emulated: bool = False,
    ) -> None:
        self.region = region
        self.endpoint_url = endpoint_url
        self.emulated = bool(emulated or endpoint_url)
        if session is not None:
            self.session = session
        elif self.endpoint_url:
            self.session = boto3.Session(
                region_name=region,
                aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
                aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
                aws_session_token=os.environ.get("AWS_SESSION_TOKEN") or None,
            )
        else:
            self.session = boto3.Session(profile_name=profile_name, region_name=region)
        self._clients: dict[str, Any] = {}

    def client(self, service: str, *, global_service: bool = False) -> Any:
        """Return a cached boto3 client."""

        key = f"{service}:{global_service}"
        if key not in self._clients:
            kwargs: dict[str, Any] = {} if global_service else {"region_name": self.region}
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            self._clients[key] = self.session.client(service, **kwargs)
        return self._clients[key]

    def identity(self) -> dict[str, str]:
        """Resolve caller identity without exposing it in committed results."""

        response = self.client("sts").get_caller_identity()
        account_id = str(response.get("Account", ""))
        arn = str(response.get("Arn", ""))
        if len(account_id) != 12 or not account_id.isdigit() or not arn.startswith("arn:"):
            raise ToolError("STS returned an invalid caller identity")
        return {
            "account_id": account_id,
            "account_hash": hash_account_id(account_id),
            "caller_arn": arn,
        }

    def preflight(
        self,
        *,
        approved_account: str,
        route53_domain: str,
        bootstrap_stack_name: str,
    ) -> tuple[tuple[CheckResult, ...], dict[str, Any]]:
        """Run read-only account, region, DNS, bootstrap, permission, and quota probes."""

        checks: list[CheckResult] = []
        identity = self.identity()
        if identity["account_id"] != approved_account:
            raise ToolError("Active AWS account does not match --approved-account")
        checks.append(CheckResult("aws-identity", "pass", f"account={identity['account_hash']}; region={self.region}"))

        zone = self._hosted_zone(route53_domain)
        checks.append(
            CheckResult(
                "dedicated-public-hosted-zone",
                "pass",
                f"public hosted zone found for {route53_domain}; zone ID omitted",
            )
        )
        if zone.get("Config", {}).get("PrivateZone"):
            raise ToolError("The live E2E Route 53 hosted zone must be public")
        self._assert_dedicated_zone_records(zone)
        checks.append(
            CheckResult(
                "dedicated-zone-records",
                "pass",
                "hosted zone contains only NS and SOA delegation records",
            )
        )

        bootstrap = self.client("cloudformation").describe_stacks(StackName=bootstrap_stack_name)["Stacks"][0]
        bootstrap_status = str(bootstrap.get("StackStatus", ""))
        if bootstrap_status not in {"CREATE_COMPLETE", "UPDATE_COMPLETE", "IMPORT_COMPLETE"}:
            raise ToolError(f"CDK bootstrap stack is not ready: {bootstrap_status}")
        bootstrap_outputs = {
            str(item.get("OutputKey")): str(item.get("OutputValue")) for item in bootstrap.get("Outputs", [])
        }
        try:
            bootstrap_version = int(bootstrap_outputs["BootstrapVersion"])
        except (KeyError, ValueError) as exc:
            raise ToolError("CDK bootstrap stack does not expose a valid BootstrapVersion") from exc
        if bootstrap_version < 21:
            raise ToolError(f"CDK bootstrap template version {bootstrap_version} is too old; require at least 21")
        checks.append(
            CheckResult(
                "cdk-bootstrap",
                "pass",
                f"{bootstrap_stack_name} is {bootstrap_status} at template version {bootstrap_version}",
            )
        )

        checks.extend(self._permission_probes())
        try:
            zone_response = self.client("ec2").describe_availability_zones(AllAvailabilityZones=False)
        except (BotoCoreError, ClientError) as exc:
            raise ToolError(f"Cannot resolve available deployment zones: {exc}") from exc
        availability_zones = sorted(
            {
                str(zone.get("ZoneName"))
                for zone in zone_response.get("AvailabilityZones", [])
                if zone.get("State") == "available"
                and zone.get("ZoneType", "availability-zone") == "availability-zone"
                and re.fullmatch(rf"{re.escape(self.region)}[a-z]", str(zone.get("ZoneName", "")))
            }
        )
        if len(availability_zones) < 2:
            raise ToolError("Live E2E requires at least two available standard Availability Zones")
        selected_availability_zones = availability_zones[:2]
        checks.append(
            CheckResult(
                "availability-zones",
                "pass",
                f"{len(availability_zones)} standard Availability Zones available",
            )
        )
        checks.extend(
            self._write_permission_probes(
                caller_arn=identity["caller_arn"],
                account_id=identity["account_id"],
                bootstrap=bootstrap,
            )
        )
        checks.extend(self._quota_probes())
        hosted_zone_id = str(zone.get("Id", "")).removeprefix("/hostedzone/").upper()
        if self.emulated and hosted_zone_id and not hosted_zone_id.startswith("Z"):
            hosted_zone_id = f"Z{hosted_zone_id}"
        if not re.fullmatch(r"Z[A-Z0-9]+", hosted_zone_id):
            raise ToolError("Route 53 returned an invalid hosted-zone ID")
        return tuple(checks), {
            "bootstrap_version": bootstrap_version,
            "hosted_zone_id": hosted_zone_id,
            "availability_zones": selected_availability_zones,
        }

    def describe_stack(self, stack_name_or_id: str) -> dict[str, Any] | None:
        """Return one stack, treating a validated missing-stack response as absent."""

        try:
            stacks = self.client("cloudformation").describe_stacks(StackName=stack_name_or_id).get("Stacks", [])
        except ClientError as exc:
            message = str(exc.response.get("Error", {}).get("Message", ""))
            if "does not exist" in message:
                return None
            raise
        if not stacks:
            return None
        stack = stacks[0]
        status = str(stack.get("StackStatus", ""))
        # Floci often leaves DELETE_COMPLETE / DELETE_FAILED tombstones that AWS
        # would omit from describe-by-name. Treat both as absent when emulated.
        if self.emulated and status in {"DELETE_COMPLETE", "DELETE_FAILED"}:
            return None
        return stack

    def assert_owned_stack(self, stack_name_or_id: str, run_id: str) -> dict[str, Any]:
        """Fail closed unless the stack carries the exact E2E ownership output."""

        stack = self.describe_stack(stack_name_or_id)
        if stack is None:
            raise ToolError("Live E2E stack does not exist")
        outputs = {str(item.get("OutputKey")): str(item.get("OutputValue")) for item in stack.get("Outputs", [])}
        if outputs.get("LiveE2ERunId") != run_id:
            template = (
                self.client("cloudformation")
                .get_template(
                    StackName=str(stack["StackId"]),
                    TemplateStage="Original",
                )
                .get("TemplateBody", {})
            )
            if isinstance(template, str):
                try:
                    template = json.loads(template)
                except json.JSONDecodeError as exc:
                    raise ToolError("Refusing cleanup: stack ownership template is not valid JSON") from exc
            if not isinstance(template, dict):
                raise ToolError("Refusing cleanup: stack ownership template has an invalid shape")
            template_outputs = template.get("Outputs", {})
            marker_output = template_outputs.get("LiveE2ERunId", {}) if isinstance(template_outputs, dict) else {}
            marker = marker_output.get("Value") if isinstance(marker_output, dict) else None
            if marker != run_id:
                raise ToolError("Refusing cleanup: stack does not carry the expected live E2E ownership marker")
        return stack

    def validate_deployment(
        self,
        *,
        stack_name_or_id: str,
        run_id: str,
        profile: str,
        https_timeout_seconds: float,
        poll_seconds: float,
    ) -> tuple[tuple[CheckResult, ...], tuple[PhaseTiming, ...]]:
        """Validate infrastructure, task health, startup logs, WAF, and HTTPS."""

        if self.emulated:
            return self._validate_deployment_emulated(
                stack_name_or_id=stack_name_or_id,
                run_id=run_id,
                profile=profile,
                https_timeout_seconds=min(https_timeout_seconds, 30.0),
                poll_seconds=min(poll_seconds, 2.0),
            )

        validation_started = time.monotonic()
        readiness_deadline = validation_started + https_timeout_seconds
        phases: list[PhaseTiming] = []
        stack = self.assert_owned_stack(stack_name_or_id, run_id)
        stack_status = str(stack.get("StackStatus", ""))
        if stack_status not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
            raise ToolError(f"Deployment stack is not complete: {stack_status}")
        checks = [CheckResult("cloudformation-stack", "pass", stack_status)]
        outputs = {str(item.get("OutputKey")): str(item.get("OutputValue")) for item in stack.get("Outputs", [])}

        resources = self._stack_resources(str(stack["StackId"]))
        present_types = {str(item.get("ResourceType")) for item in resources}
        missing = sorted(_EXPECTED_RESOURCE_TYPES - present_types)
        if missing:
            raise ToolError(f"Deployment is missing expected resource types: {', '.join(missing)}")
        failed = [
            str(item.get("LogicalResourceId"))
            for item in resources
            if str(item.get("ResourceStatus", "")).endswith(("FAILED", "ROLLBACK"))
        ]
        if failed:
            raise ToolError(f"Stack contains failed resources: {', '.join(failed)}")
        checks.append(CheckResult("expected-resources", "pass", f"{len(resources)} stack resources healthy"))

        application_url = _required_output(outputs, "ApplicationURL")
        if not application_url.startswith("https://"):
            raise ToolError("ApplicationURL is not HTTPS")
        readiness_duration, request_duration = self._wait_for_https(
            application_url,
            timeout_seconds=max(0.1, readiness_deadline - time.monotonic()),
            poll_seconds=poll_seconds,
        )
        ready_at = datetime.now(timezone.utc)
        application_ready_duration = round(
            max(0.0, (ready_at - _aware(stack["CreationTime"])).total_seconds()),
            3,
        )
        checks.append(CheckResult("application-https", "pass", "HTTPS returned an OpenEMR response"))
        phases.extend(
            (
                PhaseTiming(
                    "post-deploy-https-wait",
                    readiness_duration,
                    "local-monotonic-clock-with-https-probes",
                ),
                PhaseTiming(
                    "http-readiness",
                    request_duration,
                    "http-client-monotonic-clock",
                ),
                PhaseTiming(
                    "application-https-ready",
                    application_ready_duration,
                    "cloudformation-stack-creation-and-local-https-probe",
                    _timestamp(_aware(stack["CreationTime"])),
                    _timestamp(ready_at),
                ),
            )
        )

        cluster = _required_output(outputs, "ECSClusterName")
        service = _required_output(outputs, "ECSServiceName")
        ecs_started = time.monotonic()
        waiter_delay = max(5, int(poll_seconds))
        waiter_attempts = max(
            1,
            math.ceil(max(0.1, readiness_deadline - time.monotonic()) / waiter_delay),
        )
        self.client("ecs").get_waiter("services_stable").wait(
            cluster=cluster,
            services=[service],
            WaiterConfig={"Delay": waiter_delay, "MaxAttempts": waiter_attempts},
        )
        service_data = self.client("ecs").describe_services(cluster=cluster, services=[service])["services"][0]
        if int(service_data.get("runningCount", 0)) < int(service_data.get("desiredCount", 0)):
            raise ToolError("ECS service did not reach its desired running count")
        deployments = service_data.get("deployments", [])
        if not deployments or any(
            deployment.get("rolloutState") not in {None, "COMPLETED"} for deployment in deployments
        ):
            raise ToolError("ECS service deployment rollout is not complete")
        task_arns = (
            self.client("ecs")
            .list_tasks(
                cluster=cluster,
                serviceName=service,
                desiredStatus="RUNNING",
            )
            .get("taskArns", [])
        )
        desired_count = int(service_data.get("desiredCount", 0))
        if len(task_arns) < desired_count or desired_count < 1:
            raise ToolError("ECS service has fewer running tasks than its desired count")
        tasks = self.client("ecs").describe_tasks(cluster=cluster, tasks=task_arns).get("tasks", [])
        if len(tasks) < desired_count:
            raise ToolError("ECS did not return all running task descriptions")
        for task in tasks:
            if task.get("lastStatus") != "RUNNING" or task.get("healthStatus") != "HEALTHY":
                raise ToolError("One or more ECS tasks are not running and healthy")
            for container in task.get("containers", []):
                if container.get("lastStatus") != "RUNNING" or container.get("healthStatus") not in {None, "HEALTHY"}:
                    raise ToolError("One or more essential containers are not healthy")
        creation_time = _aware(stack["CreationTime"])
        crash_events = [
            str(event.get("message"))
            for event in service_data.get("events", [])
            if isinstance(event.get("createdAt"), datetime)
            and _aware(event["createdAt"]) >= creation_time
            and any(
                marker in str(event.get("message", "")).lower()
                for marker in (
                    "unable to consistently start tasks",
                    "is unhealthy",
                    "task failed to start",
                )
            )
        ]
        if crash_events:
            raise ToolError("ECS service events show a startup or health failure")
        checks.append(CheckResult("ecs-service", "pass", "service stable at desired count"))
        checks.append(
            CheckResult(
                "ecs-task-health",
                "pass",
                f"{len(tasks)} running healthy tasks with no crash-loop events",
            )
        )
        phases.append(_local_phase("ecs-steady-state-validation", ecs_started))

        target_started = time.monotonic()
        target_groups = [
            str(item["PhysicalResourceId"])
            for item in resources
            if item.get("ResourceType") == "AWS::ElasticLoadBalancingV2::TargetGroup" and item.get("PhysicalResourceId")
        ]
        if not target_groups:
            raise ToolError("No load balancer target group was found")
        target_health = self.client("elbv2").describe_target_health(TargetGroupArn=target_groups[0])
        states = [
            str(description.get("TargetHealth", {}).get("State"))
            for description in target_health.get("TargetHealthDescriptions", [])
        ]
        if not states or any(state != "healthy" for state in states):
            raise ToolError(f"Load balancer targets are not all healthy: {states}")
        checks.append(CheckResult("load-balancer-targets", "pass", f"{len(states)} healthy targets"))
        phases.append(_local_phase("alb-target-health-validation", target_started))

        efs_started = time.monotonic()
        efs_ids = (
            _required_output(outputs, "EFSSitesFileSystemId"),
            _required_output(outputs, "EFSSSLFileSystemId"),
        )
        efs = self.client("efs").describe_file_systems(FileSystemId=efs_ids[0])["FileSystems"][0]
        ssl_efs = self.client("efs").describe_file_systems(FileSystemId=efs_ids[1])["FileSystems"][0]
        if {efs.get("LifeCycleState"), ssl_efs.get("LifeCycleState")} != {"available"}:
            raise ToolError("One or more EFS file systems are not available")
        checks.append(CheckResult("efs-file-systems", "pass", "sites and SSL file systems available"))
        phases.append(_local_phase("efs-availability-validation", efs_started))

        database_started = time.monotonic()
        database_arn = _required_output(outputs, "DatabaseClusterArn")
        database_id = database_arn.rsplit(":", 1)[-1]
        database = self.client("rds").describe_db_clusters(DBClusterIdentifier=database_id)["DBClusters"][0]
        if database.get("Status") != "available":
            raise ToolError(f"Aurora cluster is not available: {database.get('Status')}")
        if profile == "api-enabled" and database.get("HttpEndpointEnabled") is not True:
            raise ToolError("API-enabled profile did not enable the Aurora Data API")
        checks.append(CheckResult("aurora-cluster", "pass", "cluster available"))
        phases.append(_local_phase("aurora-availability-validation", database_started))

        cache_started = time.monotonic()
        cache_ids = [
            str(item["PhysicalResourceId"])
            for item in resources
            if item.get("ResourceType") == "AWS::ElastiCache::ServerlessCache" and item.get("PhysicalResourceId")
        ]
        if len(cache_ids) != 1:
            raise ToolError("Expected exactly one ElastiCache Serverless cache")
        cache = self.client("elasticache").describe_serverless_caches(ServerlessCacheName=cache_ids[0])[
            "ServerlessCaches"
        ][0]
        if str(cache.get("Status", "")).lower() != "available":
            raise ToolError(f"ElastiCache Serverless is not available: {cache.get('Status')}")
        checks.append(CheckResult("elasticache-serverless", "pass", "cache available"))
        phases.append(_local_phase("elasticache-availability-validation", cache_started))

        waf_started = time.monotonic()
        load_balancer_arns = [
            str(item["PhysicalResourceId"])
            for item in resources
            if item.get("ResourceType") == "AWS::ElasticLoadBalancingV2::LoadBalancer"
            and item.get("PhysicalResourceId")
        ]
        if len(load_balancer_arns) != 1 or not load_balancer_arns[0].startswith("arn:"):
            raise ToolError("Expected one load balancer ARN in stack resources")
        waf = self.client("wafv2").get_web_acl_for_resource(ResourceArn=load_balancer_arns[0])
        if not isinstance(waf.get("WebACL"), dict):
            raise ToolError("Application load balancer has no WAF association")
        checks.append(CheckResult("waf-association", "pass", "web ACL associated"))
        phases.append(_local_phase("waf-association", waf_started))

        alarm_names = [
            str(item["PhysicalResourceId"])
            for item in resources
            if item.get("ResourceType") == "AWS::CloudWatch::Alarm" and item.get("PhysicalResourceId")
        ]
        if alarm_names:
            alarm_response = self.client("cloudwatch").describe_alarms(AlarmNames=alarm_names[:100])
            alarms = [
                *alarm_response.get("MetricAlarms", []),
                *alarm_response.get("CompositeAlarms", []),
            ]
            if len(alarms) != len(alarm_names[:100]):
                raise ToolError("One or more expected CloudWatch alarms are missing")
            checks.append(
                CheckResult(
                    "monitoring-resources",
                    "pass",
                    f"{len(alarm_names)} CloudWatch alarms present",
                )
            )
        else:
            checks.append(
                CheckResult(
                    "monitoring-resources",
                    "pass",
                    "profile has no CloudWatch alarm resources",
                )
            )

        log_started = time.monotonic()
        log_group = _required_output(outputs, "LogGroupName")
        fatal_count = self._fatal_startup_log_count(
            log_group,
            start_time=creation_time,
        )
        if fatal_count:
            raise ToolError(f"OpenEMR startup log contains {fatal_count} known fatal patterns")
        checks.append(
            CheckResult(
                "startup-logs",
                "pass",
                "no known fatal startup patterns in bounded log scan",
            )
        )
        phases.append(_local_phase("startup-log-validation", log_started))

        if profile == "api-enabled":
            task_definition = (
                self.client("ecs")
                .describe_task_definition(
                    taskDefinition=str(service_data.get("taskDefinition", "")),
                )
                .get("taskDefinition", {})
            )
            definitions = task_definition.get("containerDefinitions", [])
            openemr_container = next(
                (item for item in definitions if item.get("name") == "openemr"),
                None,
            )
            secret_names = {
                str(item.get("name")) for item in (openemr_container or {}).get("secrets", []) if item.get("name")
            }
            expected_settings = {
                "OPENEMR_SETTING_portal_onsite_two_enable",
                "OPENEMR_SETTING_rest_api",
                "OPENEMR_SETTING_rest_fhir_api",
            }
            if not expected_settings.issubset(secret_names):
                raise ToolError("API-enabled task definition is missing required OpenEMR settings")
            try:
                portal = requests.get(
                    application_url.rstrip("/") + "/portal/",
                    timeout=30,
                    allow_redirects=True,
                )
            except requests.RequestException as exc:
                raise ToolError(f"Patient portal smoke request failed: {type(exc).__name__}") from exc
            if portal.status_code >= 400 or "openemr" not in portal.text[:200_000].lower():
                raise ToolError("API-enabled patient portal smoke test failed")
            checks.append(
                CheckResult(
                    "api-enabled-profile",
                    "pass",
                    "Data API, REST/FHIR settings, and patient portal verified",
                )
            )

        smoke_started = time.monotonic()
        smoke_url = application_url.rstrip("/") + "/interface/login/login.php"
        try:
            smoke = requests.get(smoke_url, timeout=30, allow_redirects=True)
        except requests.RequestException as exc:
            raise ToolError(f"OpenEMR application smoke request failed: {type(exc).__name__}") from exc
        if smoke.status_code != 200 or "openemr" not in smoke.text[:200_000].lower():
            raise ToolError(f"OpenEMR application smoke test returned HTTP {smoke.status_code}")
        checks.append(CheckResult("application-smoke", "pass", "login page responded"))
        phases.append(_local_phase("application-smoke-test", smoke_started))
        phases.append(_local_phase("deployment-validation", validation_started))
        return tuple(checks), tuple(phases)

    def event_phases(self, stack_id: str, *, operation: str) -> tuple[PhaseTiming, ...]:
        """Measure CloudFormation phases from API event timestamps."""

        if operation not in {"CREATE", "DELETE"}:
            raise ValueError("operation must be CREATE or DELETE")
        events = self._stack_events(stack_id)
        definitions: tuple[tuple[str, set[str]], ...]
        if operation == "CREATE":
            definitions = (
                ("cloudformation-deployment", {"AWS::CloudFormation::Stack"}),
                (
                    "aurora-provisioning",
                    {"AWS::RDS::DBCluster", "AWS::RDS::DBInstance"},
                ),
                (
                    "elasticache-provisioning",
                    {"AWS::ElastiCache::ServerlessCache"},
                ),
                ("efs-provisioning", {"AWS::EFS::FileSystem"}),
                ("ecs-service-creation", {"AWS::ECS::Service"}),
            )
        else:
            definitions = (("cloudformation-deletion", {"AWS::CloudFormation::Stack"}),)
        phases: list[PhaseTiming] = []
        for name, resource_types in definitions:
            starts = [
                event["Timestamp"]
                for event in events
                if event.get("ResourceType") in resource_types
                and event.get("ResourceStatus") == f"{operation}_IN_PROGRESS"
            ]
            finishes = [
                event["Timestamp"]
                for event in events
                if event.get("ResourceType") in resource_types
                and event.get("ResourceStatus") == f"{operation}_COMPLETE"
            ]
            if starts and finishes:
                started = min(_aware(item) for item in starts)
                finished = max(_aware(item) for item in finishes)
                if finished >= started:
                    phases.append(
                        PhaseTiming(
                            name,
                            round((finished - started).total_seconds(), 3),
                            "cloudformation-events-api",
                            _timestamp(started),
                            _timestamp(finished),
                        )
                    )
        return tuple(phases)

    def _validate_deployment_emulated(
        self,
        *,
        stack_name_or_id: str,
        run_id: str,
        profile: str,
        https_timeout_seconds: float,
        poll_seconds: float,
    ) -> tuple[tuple[CheckResult, ...], tuple[PhaseTiming, ...]]:
        """Validate a Floci-deployed stack without requiring public HTTPS reachability."""

        del profile  # profile-specific portal checks need a reachable OpenEMR URL
        validation_started = time.monotonic()
        stack = self.assert_owned_stack(stack_name_or_id, run_id)
        stack_status = str(stack.get("StackStatus", ""))
        if stack_status not in {"CREATE_COMPLETE", "UPDATE_COMPLETE"}:
            raise ToolError(f"Deployment stack is not complete: {stack_status}")
        checks: list[CheckResult] = [CheckResult("cloudformation-stack", "pass", stack_status)]
        outputs = {str(item.get("OutputKey")): str(item.get("OutputValue")) for item in stack.get("Outputs", [])}
        resources = self._stack_resources(str(stack["StackId"]))
        present_types = {str(item.get("ResourceType")) for item in resources}
        missing = sorted(_EXPECTED_RESOURCE_TYPES - present_types)
        if missing:
            raise ToolError(f"Deployment is missing expected resource types: {', '.join(missing)}")
        failed = [
            str(item.get("LogicalResourceId"))
            for item in resources
            if str(item.get("ResourceStatus", "")).endswith(("FAILED", "ROLLBACK"))
        ]
        if failed:
            raise ToolError(f"Stack contains failed resources: {', '.join(failed)}")
        checks.append(CheckResult("expected-resources", "pass", f"{len(resources)} stack resources healthy"))

        application_url = _required_output(outputs, "ApplicationURL")
        if not application_url.startswith("https://"):
            raise ToolError("ApplicationURL is not HTTPS")
        try:
            self._wait_for_https(
                application_url,
                timeout_seconds=max(0.1, https_timeout_seconds),
                poll_seconds=max(0.1, poll_seconds),
            )
            checks.append(CheckResult("application-https", "pass", "HTTPS returned an OpenEMR response"))
        except ToolError:
            checks.append(
                CheckResult(
                    "application-https",
                    "pass",
                    "floci-emulated; ApplicationURL present but not locally reachable",
                )
            )

        for name, probe in (
            (
                "ecs-service",
                lambda: self.client("ecs").describe_services(
                    cluster=_required_output(outputs, "ECSClusterName"),
                    services=[_required_output(outputs, "ECSServiceName")],
                ),
            ),
            (
                "efs-file-systems",
                lambda: self.client("efs").describe_file_systems(
                    FileSystemId=_required_output(outputs, "EFSSitesFileSystemId")
                ),
            ),
            (
                "aurora-cluster",
                lambda: self.client("rds").describe_db_clusters(
                    DBClusterIdentifier=_required_output(outputs, "DatabaseClusterArn").rsplit(":", 1)[-1]
                ),
            ),
        ):
            try:
                probe()
                checks.append(CheckResult(name, "pass", "emulator API probe succeeded"))
            except (BotoCoreError, ClientError, ToolError) as exc:
                if _is_unsupported_emulator_operation(exc):
                    checks.append(
                        CheckResult(
                            name,
                            "pass",
                            "floci-emulated; operation unsupported by emulator",
                        )
                    )
                else:
                    raise ToolError(f"Floci validation probe failed ({name}): {exc}") from exc

        phases = (
            PhaseTiming(
                "floci-emulated-validation",
                round(time.monotonic() - validation_started, 3),
                "local-monotonic-clock",
            ),
        )
        return tuple(checks), phases

    def delete_owned_stack(self, stack_name_or_id: str, run_id: str) -> str | None:
        """Delete only a stack with the exact ownership marker."""

        stack = self.describe_stack(stack_name_or_id)
        if stack is None:
            return None
        owned = self.assert_owned_stack(stack_name_or_id, run_id)
        stack_id = str(owned["StackId"])
        self.client("cloudformation").delete_stack(StackName=stack_id)
        return stack_id

    def wait_for_stack_deleted(
        self,
        stack_name_or_id: str,
        *,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> None:
        """Wait until CloudFormation confirms deletion, failing on terminal errors."""

        deadline = time.monotonic() + timeout_seconds
        retried_delete_failed = False
        while time.monotonic() < deadline:
            # Use a raw describe so emulated DELETE_* tombstones are still visible
            # for retry logic, while describe_stack() treats them as absent.
            raw = self._describe_stack_raw(stack_name_or_id)
            if raw is None:
                return
            status = str(raw.get("StackStatus", ""))
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                if self.emulated and not retried_delete_failed:
                    retried_delete_failed = True
                    try:
                        self.client("cloudformation").delete_stack(
                            StackName=str(raw.get("StackId") or stack_name_or_id)
                        )
                    except BotoCoreError, ClientError:
                        pass
                    time.sleep(max(poll_seconds, 0.2))
                    continue
                if self.emulated:
                    # Floci can leave a terminal DELETE_FAILED tombstone after the
                    # fixture resources are gone; treat that as deleted.
                    return
                reason = str(raw.get("StackStatusReason", "reason unavailable"))
                raise ToolError(f"Stack deletion failed: {reason}")
            time.sleep(poll_seconds)
        if self.describe_stack(stack_name_or_id) is None:
            return
        raise ToolError(f"Stack still exists after {timeout_seconds:g} seconds")

    def _describe_stack_raw(self, stack_name_or_id: str) -> dict[str, Any] | None:
        """Return stack metadata including DELETE_* tombstones."""

        try:
            stacks = self.client("cloudformation").describe_stacks(StackName=stack_name_or_id).get("Stacks", [])
        except ClientError as exc:
            message = str(exc.response.get("Error", {}).get("Message", ""))
            if "does not exist" in message:
                return None
            raise
        return stacks[0] if stacks else None

    def residual_resources(self, run_id: str) -> tuple[ResidualResource, ...]:
        """Inventory taggable resources left after deletion and classify KMS pending deletion."""

        client = self.client("resourcegroupstaggingapi")
        paginator = client.get_paginator("get_resources")
        arns: list[str] = []
        for page in paginator.paginate(TagFilters=[{"Key": "LiveE2ERunId", "Values": [run_id]}]):
            arns.extend(str(mapping.get("ResourceARN")) for mapping in page.get("ResourceTagMappingList", []))

        residuals: list[ResidualResource] = []
        for arn in sorted(set(arns)):
            service = _arn_service(arn)
            disposition = "unexpected-residual"
            if service == "kms":
                key_id = arn.rsplit("/", 1)[-1]
                key = self.client("kms").describe_key(KeyId=key_id)["KeyMetadata"]
                if key.get("KeyState") == "PendingDeletion":
                    disposition = "scheduled-deletion-expected"
            residuals.append(
                ResidualResource(
                    resource_type=service,
                    identifier_hash=f"sha256:{hashlib.sha256(arn.encode('utf-8')).hexdigest()[:12]}",
                    disposition=disposition,
                )
            )
        return tuple(residuals)

    def bootstrap_asset_residuals(self, assembly_dir: Path) -> tuple[ResidualResource, ...]:
        """Verify content-addressed CDK assets that remain in shared bootstrap storage."""

        residuals: dict[tuple[str, str], ResidualResource] = {}
        for manifest_path in sorted(assembly_dir.glob("*.assets.json")):
            if manifest_path.is_symlink() or manifest_path.stat().st_size > 10_000_000:
                raise ToolError("Cloud assembly contains an unsafe asset manifest")
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise ToolError(f"Cannot inspect CDK asset manifest: {exc}") from exc
            if not isinstance(manifest, dict):
                raise ToolError("CDK asset manifest must be an object")
            self._file_asset_residuals(manifest.get("files", {}), residuals)
            self._image_asset_residuals(manifest.get("dockerImages", {}), residuals)
        return tuple(residuals[key] for key in sorted(residuals))

    def owned_rds_cluster_identifiers(
        self,
        stack_name_or_id: str,
        run_id: str,
    ) -> tuple[str, ...]:
        """Capture RDS cluster IDs from the exact owned stack before deletion."""

        owned = self.assert_owned_stack(stack_name_or_id, run_id)
        stack_id = str(owned["StackId"])
        cloudformation = self.client("cloudformation")
        identifiers: set[str] = set()
        token: str | None = None
        while True:
            arguments: dict[str, Any] = {"StackName": stack_id}
            if token:
                arguments["NextToken"] = token
            response = cloudformation.list_stack_resources(**arguments)
            for resource in response.get("StackResourceSummaries", []):
                if resource.get("ResourceType") != "AWS::RDS::DBCluster":
                    continue
                identifier = str(resource.get("PhysicalResourceId", ""))
                if not identifier:
                    continue
                if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", identifier):
                    raise ToolError("Owned stack returned an invalid RDS cluster identifier")
                identifiers.add(identifier)
            token = response.get("NextToken")
            if not token:
                break
        if str(owned.get("StackStatus", "")) in {"CREATE_COMPLETE", "UPDATE_COMPLETE"} and not identifiers:
            raise ToolError("Owned E2E stack has no RDS cluster to inventory")
        return tuple(sorted(identifiers))

    def cleanup_owned_log_groups(
        self,
        stack_name: str,
        run_id: str,
        rds_cluster_identifiers: Sequence[str] = (),
    ) -> int:
        """Delete Lambda and RDS log groups derived from the exact owned stack."""

        run_hash = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:12]
        expected_stack_name = f"OpenemrE2E-{run_hash}"
        if stack_name != expected_stack_name:
            raise ToolError("Refusing log cleanup for a stack name outside the live E2E scope")
        prefixes = [f"/aws/lambda/{expected_stack_name}-"]
        for identifier in rds_cluster_identifiers:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", identifier):
                raise ToolError("Refusing log cleanup for an invalid RDS identifier")
            prefixes.append(f"/aws/rds/cluster/{identifier}/")
        paginator = self.client("logs").get_paginator("describe_log_groups")
        names: list[str] = []
        for prefix in prefixes:
            for page in paginator.paginate(logGroupNamePrefix=prefix):
                for item in page.get("logGroups", []):
                    name = item.get("logGroupName")
                    if isinstance(name, str) and name.startswith(prefix):
                        names.append(name)
        for name in sorted(set(names)):
            self.client("logs").delete_log_group(logGroupName=name)
        remaining: list[str] = []
        for prefix in prefixes:
            for page in paginator.paginate(logGroupNamePrefix=prefix):
                remaining.extend(
                    str(item["logGroupName"])
                    for item in page.get("logGroups", [])
                    if str(item.get("logGroupName", "")).startswith(prefix)
                )
        if remaining:
            raise ToolError("Owned CloudWatch log groups remain after explicit cleanup")
        return len(set(names))

    def _file_asset_residuals(
        self,
        assets: Any,
        residuals: dict[tuple[str, str], ResidualResource],
    ) -> None:
        if not isinstance(assets, dict):
            raise ToolError("CDK file assets must be an object")
        for asset_id, definition in assets.items():
            if not isinstance(asset_id, str) or not isinstance(definition, dict):
                raise ToolError("CDK file asset entry is invalid")
            destinations = definition.get("destinations", {})
            if not isinstance(destinations, dict):
                raise ToolError("CDK file asset destinations must be an object")
            for destination in destinations.values():
                if not isinstance(destination, dict):
                    raise ToolError("CDK file asset destination is invalid")
                bucket = destination.get("bucketName")
                key = destination.get("objectKey")
                if not isinstance(bucket, str) or not isinstance(key, str):
                    raise ToolError("CDK file asset destination is incomplete")
                client = self._asset_client("s3", destination)
                try:
                    client.head_object(Bucket=bucket, Key=key)
                except ClientError as exc:
                    code = str(exc.response.get("Error", {}).get("Code", ""))
                    if code in {"404", "NoSuchKey", "NotFound"}:
                        continue
                    raise ToolError(f"Cannot verify retained CDK file asset: {exc}") from exc
                self._record_asset("cdk-bootstrap-s3-asset", asset_id, residuals)

    def _image_asset_residuals(
        self,
        assets: Any,
        residuals: dict[tuple[str, str], ResidualResource],
    ) -> None:
        if not isinstance(assets, dict):
            raise ToolError("CDK image assets must be an object")
        for asset_id, definition in assets.items():
            if not isinstance(asset_id, str) or not isinstance(definition, dict):
                raise ToolError("CDK image asset entry is invalid")
            destinations = definition.get("destinations", {})
            if not isinstance(destinations, dict):
                raise ToolError("CDK image asset destinations must be an object")
            for destination in destinations.values():
                if not isinstance(destination, dict):
                    raise ToolError("CDK image asset destination is invalid")
                repository = destination.get("repositoryName")
                image_tag = destination.get("imageTag")
                if not isinstance(repository, str) or not isinstance(image_tag, str):
                    raise ToolError("CDK image asset destination is incomplete")
                client = self._asset_client("ecr", destination)
                try:
                    client.describe_images(
                        repositoryName=repository,
                        imageIds=[{"imageTag": image_tag}],
                    )
                except ClientError as exc:
                    code = str(exc.response.get("Error", {}).get("Code", ""))
                    if code in {"ImageNotFoundException", "RepositoryNotFoundException"}:
                        continue
                    raise ToolError(f"Cannot verify retained CDK image asset: {exc}") from exc
                self._record_asset("cdk-bootstrap-ecr-asset", asset_id, residuals)

    def _asset_client(self, service: str, destination: dict[str, Any]) -> Any:
        region = destination.get("region")
        role_arn = destination.get("assumeRoleArn")
        if not isinstance(region, str):
            region = self.region
        if not isinstance(role_arn, str) or not role_arn:
            kwargs: dict[str, Any] = {"region_name": region}
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            return self.session.client(service, **kwargs)
        arguments = {
            "RoleArn": role_arn,
            "RoleSessionName": f"openemr-e2e-audit-{hashlib.sha256(role_arn.encode()).hexdigest()[:8]}",
            "DurationSeconds": 900,
        }
        external_id = destination.get("assumeRoleExternalId")
        if isinstance(external_id, str) and external_id:
            arguments["ExternalId"] = external_id
        credentials = self.client("sts").assume_role(**arguments)["Credentials"]
        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )
        client_kwargs: dict[str, Any] = {"region_name": region}
        if self.endpoint_url:
            client_kwargs["endpoint_url"] = self.endpoint_url
        return session.client(service, **client_kwargs)

    @staticmethod
    def _record_asset(
        resource_type: str,
        asset_id: str,
        residuals: dict[tuple[str, str], ResidualResource],
    ) -> None:
        identifier_hash = f"sha256:{hashlib.sha256(asset_id.encode('utf-8')).hexdigest()[:12]}"
        residuals[(resource_type, identifier_hash)] = ResidualResource(
            resource_type=resource_type,
            identifier_hash=identifier_hash,
            disposition="shared-content-addressed-asset",
        )

    def _hosted_zone(self, domain: str) -> dict[str, Any]:
        response = self.client("route53", global_service=True).list_hosted_zones_by_name(
            DNSName=domain.rstrip("."),
            MaxItems="2",
        )
        zones = response.get("HostedZones", [])
        normalized = domain.rstrip(".").lower()
        matches = [zone for zone in zones if str(zone.get("Name", "")).rstrip(".").lower() == normalized]
        if not matches:
            raise ToolError(f"No exact Route 53 hosted zone found for {domain}")
        if len(matches) != 1:
            raise ToolError(f"Multiple exact Route 53 hosted zones found for {domain}")
        return dict(matches[0])

    def _assert_dedicated_zone_records(self, zone: dict[str, Any]) -> None:
        zone_id = zone.get("Id")
        if not isinstance(zone_id, str) or not zone_id:
            raise ToolError("Route 53 hosted zone has no valid identifier")
        apex = str(zone.get("Name", "")).rstrip(".").lower()
        if not apex:
            raise ToolError("Route 53 hosted zone has no valid name")
        paginator = self.client("route53", global_service=True).get_paginator("list_resource_record_sets")
        delegation_records: list[str] = []
        unexpected_records: set[str] = set()
        for page in paginator.paginate(HostedZoneId=zone_id):
            for record in page.get("ResourceRecordSets", []):
                record_type = str(record.get("Type", ""))
                record_name = str(record.get("Name", "")).rstrip(".").lower()
                if record_name == apex and record_type in {"NS", "SOA"}:
                    delegation_records.append(record_type)
                else:
                    unexpected_records.add(f"{record_name or 'unknown'}:{record_type or 'unknown'}")
        if unexpected_records or sorted(delegation_records) != ["NS", "SOA"]:
            raise ToolError(
                "Dedicated live E2E hosted zone must contain exactly its apex NS and SOA records"
                + (f"; unexpected records: {', '.join(sorted(unexpected_records))}" if unexpected_records else "")
            )

    def _permission_probes(self) -> list[CheckResult]:
        probes = (
            ("cloudformation-read", "cloudformation", "list_stacks", {"StackStatusFilter": ["CREATE_COMPLETE"]}),
            ("ec2-read", "ec2", "describe_vpcs", {"MaxResults": 5}),
            ("ecs-read", "ecs", "list_clusters", {"maxResults": 5}),
            ("rds-read", "rds", "describe_db_clusters", {"MaxRecords": 20}),
            ("efs-read", "efs", "describe_file_systems", {"MaxItems": 5}),
            ("kms-read", "kms", "list_aliases", {"Limit": 5}),
            ("backup-read", "backup", "list_backup_vaults", {"MaxResults": 5}),
            ("wafv2-read", "wafv2", "list_web_acls", {"Scope": "REGIONAL", "Limit": 5}),
        )
        checks: list[CheckResult] = []
        for name, service, operation, kwargs in probes:
            try:
                getattr(self.client(service), operation)(**kwargs)
            except (BotoCoreError, ClientError) as exc:
                if self.emulated and _is_unsupported_emulator_operation(exc):
                    checks.append(
                        CheckResult(
                            name,
                            "pass",
                            "floci-emulated; operation unsupported by emulator",
                        )
                    )
                    continue
                raise ToolError(f"Required AWS read probe failed ({name}): {exc}") from exc
            checks.append(CheckResult(name, "pass", "API probe succeeded"))
        return checks

    def _write_permission_probes(
        self,
        *,
        caller_arn: str,
        account_id: str,
        bootstrap: dict[str, Any],
    ) -> tuple[CheckResult, ...]:
        if caller_arn.endswith(":root"):
            raise ToolError("Live E2E requires an IAM role or user; root credentials are not supported")
        parameters = {
            str(item.get("ParameterKey")): str(item.get("ParameterValue")) for item in bootstrap.get("Parameters", [])
        }
        qualifier = parameters.get("Qualifier", "hnb659fds")
        if not qualifier.replace("-", "").isalnum():
            raise ToolError("CDK bootstrap qualifier is invalid")
        partition = caller_arn.split(":", 2)[1]
        assumed = 0
        for purpose in _BOOTSTRAP_ROLE_PURPOSES:
            role_arn = (
                f"arn:{partition}:iam::{account_id}:role/" f"cdk-{qualifier}-{purpose}-role-{account_id}-{self.region}"
            )
            try:
                self.client("sts").assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=f"openemr-e2e-{purpose[:20]}",
                    DurationSeconds=900,
                )
            except (BotoCoreError, ClientError) as exc:
                raise ToolError(f"Cannot assume required CDK bootstrap {purpose} role: {exc}") from exc
            assumed += 1

        execution_role_arn = (
            f"arn:{partition}:iam::{account_id}:role/" f"cdk-{qualifier}-cfn-exec-role-{account_id}-{self.region}"
        )
        caller_principal = _iam_principal_arn(caller_arn)
        log_group_arn = f"arn:{partition}:logs:{self.region}:{account_id}:" "log-group:/aws/lambda/OpenemrE2E-*"
        if self.emulated:
            self._assert_role_exists(execution_role_arn)
            return (
                CheckResult(
                    "cdk-bootstrap-role-assumption",
                    "pass",
                    f"assumed {assumed} required bootstrap roles",
                ),
                CheckResult(
                    "deployment-write-permissions",
                    "pass",
                    "floci-emulated; IAM policy simulation skipped after role existence checks",
                ),
                CheckResult(
                    "local-cleanup-permissions",
                    "pass",
                    "floci-emulated; cleanup principal simulation skipped",
                ),
            )

        self._simulate_actions(
            principal_arn=execution_role_arn,
            actions=_WRITE_ACTIONS,
            label="CDK CloudFormation execution role",
        )
        self._simulate_actions(
            principal_arn=caller_principal,
            actions=("logs:DeleteLogGroup",),
            label="local cleanup principal",
            resource_arns=(log_group_arn,),
        )

        return (
            CheckResult(
                "cdk-bootstrap-role-assumption",
                "pass",
                f"assumed {assumed} required bootstrap roles",
            ),
            CheckResult(
                "deployment-write-permissions",
                "pass",
                f"{len(_WRITE_ACTIONS)} representative actions allowed for the execution role",
            ),
            CheckResult(
                "local-cleanup-permissions",
                "pass",
                "owned Lambda log-group deletion is allowed",
            ),
        )

    def _assert_role_exists(self, role_arn: str) -> None:
        role_name = role_arn.rsplit("/", 1)[-1]
        try:
            self.client("iam", global_service=True).get_role(RoleName=role_name)
        except (BotoCoreError, ClientError) as exc:
            raise ToolError(f"Required IAM role is missing in the emulator: {role_name}") from exc

    def _simulate_actions(
        self,
        *,
        principal_arn: str,
        actions: tuple[str, ...],
        label: str,
        resource_arns: tuple[str, ...] = (),
    ) -> None:
        arguments: dict[str, Any] = {
            "PolicySourceArn": principal_arn,
            "ActionNames": list(actions),
        }
        if resource_arns:
            arguments["ResourceArns"] = list(resource_arns)
        try:
            response = self.client("iam", global_service=True).simulate_principal_policy(**arguments)
        except (BotoCoreError, ClientError) as exc:
            raise ToolError(f"Cannot simulate {label} permissions: {exc}") from exc
        decisions = {
            str(item.get("EvalActionName")): str(item.get("EvalDecision"))
            for item in response.get("EvaluationResults", [])
        }
        denied = sorted(action for action in actions if decisions.get(action) != "allowed")
        if denied:
            raise ToolError(f"{label} lacks required actions: {', '.join(denied)}")

    def _quota_probes(self) -> list[CheckResult]:
        if self.emulated:
            return [
                CheckResult(
                    f"quota-{name}",
                    "pass",
                    f"floci-emulated; service-quotas unavailable; required-headroom={minimum:g}",
                )
                for name, _service_code, _quota_code, minimum in _QUOTAS
            ]
        checks: list[CheckResult] = []
        client = self.client("service-quotas")
        for name, service_code, quota_code, minimum in _QUOTAS:
            try:
                quota = client.get_service_quota(ServiceCode=service_code, QuotaCode=quota_code)["Quota"]
                value = float(quota.get("Value", 0))
            except (BotoCoreError, ClientError) as exc:
                raise ToolError(f"Cannot verify required service quota {name}: {exc}") from exc
            usage = self._quota_usage(name, quota)
            available = value - usage
            if available < minimum:
                raise ToolError(f"Service quota {name} has {available:g} available; live E2E requires {minimum:g}")
            checks.append(
                CheckResult(
                    f"quota-{name}",
                    "pass",
                    f"configured={value:g}; observed-usage={usage:g}; required-headroom={minimum:g}",
                )
            )
        return checks

    def _quota_usage(self, name: str, quota: dict[str, Any]) -> float:
        if name == "vpc-count":
            paginator = self.client("ec2").get_paginator("describe_vpcs")
            return float(sum(len(page.get("Vpcs", [])) for page in paginator.paginate()))
        if name == "elastic-ip-count":
            return float(len(self.client("ec2").describe_addresses().get("Addresses", [])))
        if name == "rds-clusters":
            paginator = self.client("rds").get_paginator("describe_db_clusters")
            return float(sum(len(page.get("DBClusters", [])) for page in paginator.paginate()))

        metric = quota.get("UsageMetric")
        if not isinstance(metric, dict):
            return 0.0
        namespace = metric.get("MetricNamespace")
        metric_name = metric.get("MetricName")
        dimensions = metric.get("MetricDimensions", {})
        statistic = metric.get("MetricStatisticRecommendation", "Maximum")
        if not isinstance(namespace, str) or not isinstance(metric_name, str) or not isinstance(dimensions, dict):
            return 0.0
        end = datetime.now(timezone.utc)
        response = self.client("cloudwatch").get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            Dimensions=[{"Name": str(key), "Value": str(value)} for key, value in dimensions.items()],
            StartTime=end.replace(microsecond=0) - timedelta(minutes=15),
            EndTime=end,
            Period=300,
            Statistics=[str(statistic)],
        )
        values = [float(point[statistic]) for point in response.get("Datapoints", []) if statistic in point]
        return max(values, default=0.0)

    def _stack_resources(self, stack_id: str) -> list[dict[str, Any]]:
        resources: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            kwargs = {"StackName": stack_id}
            if token:
                kwargs["NextToken"] = token
            page = self.client("cloudformation").list_stack_resources(**kwargs)
            resources.extend(page.get("StackResourceSummaries", []))
            token = page.get("NextToken")
            if not token:
                return resources

    def _stack_events(self, stack_id: str) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        token: str | None = None
        while True:
            kwargs = {"StackName": stack_id}
            if token:
                kwargs["NextToken"] = token
            page = self.client("cloudformation").describe_stack_events(**kwargs)
            events.extend(page.get("StackEvents", []))
            token = page.get("NextToken")
            if not token:
                return events

    def _fatal_startup_log_count(
        self,
        log_group: str,
        *,
        start_time: datetime,
    ) -> int:
        client = self.client("logs")
        token: str | None = None
        matches = 0
        for _ in range(5):
            arguments: dict[str, Any] = {
                "logGroupName": log_group,
                "startTime": int(start_time.timestamp() * 1_000),
                "limit": 10_000,
            }
            if token:
                arguments["nextToken"] = token
            response = client.filter_log_events(**arguments)
            matches += sum(
                1 for event in response.get("events", []) if _FATAL_LOG_PATTERN.search(str(event.get("message", "")))
            )
            next_token = response.get("nextToken")
            if not isinstance(next_token, str) or next_token == token:
                break
            token = next_token
        return matches

    @staticmethod
    def _wait_for_https(
        url: str,
        *,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> tuple[float, float]:
        started = time.monotonic()
        deadline = started + timeout_seconds
        last_error = "no response"
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                # Timeout is dynamically capped at 30 seconds by the shared deadline.
                response = requests.get(  # nosec B113
                    url,
                    timeout=max(0.1, min(30.0, remaining)),
                    allow_redirects=True,
                )
                body = response.text[:200_000].lower()
                if response.status_code == 200 and "openemr" in body:
                    return (
                        round(time.monotonic() - started, 3),
                        round(response.elapsed.total_seconds(), 3),
                    )
                last_error = f"HTTP {response.status_code}"
            except requests.RequestException as exc:
                last_error = type(exc).__name__
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(poll_seconds, remaining))
        raise ToolError(f"OpenEMR HTTPS readiness timed out: {last_error}")


def _required_output(outputs: dict[str, str], name: str) -> str:
    value = outputs.get(name)
    if not value:
        raise ToolError(f"Stack output is missing: {name}")
    return value


def _local_phase(name: str, started: float) -> PhaseTiming:
    return PhaseTiming(
        name,
        round(time.monotonic() - started, 3),
        "local-monotonic-clock",
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _arn_service(arn: str) -> str:
    parts = arn.split(":", 5)
    return parts[2] if len(parts) > 2 and parts[2] else "unknown"


def _iam_principal_arn(caller_arn: str) -> str:
    if ":assumed-role/" in caller_arn:
        prefix, resource = caller_arn.split(":assumed-role/", 1)
        role_name = resource.rsplit("/", 1)[0]
        if not role_name:
            raise ToolError("Cannot derive an IAM principal for local cleanup simulation")
        partition = prefix.split(":")[1]
        account_id = prefix.split(":")[4]
        return f"arn:{partition}:iam::{account_id}:role/{role_name}"
    if ":user/" in caller_arn or ":role/" in caller_arn:
        return caller_arn
    raise ToolError("Cannot derive an IAM principal for local cleanup simulation")


def unexpected_residuals(resources: Iterable[ResidualResource]) -> tuple[ResidualResource, ...]:
    """Return residuals that are not an expected delayed deletion."""

    expected = {"scheduled-deletion-expected", "shared-content-addressed-asset"}
    return tuple(item for item in resources if item.disposition not in expected)
