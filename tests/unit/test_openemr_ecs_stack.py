"""Unit tests for OpenEMR ECS CDK stack.

Note: These tests are integration-level tests that require full stack synthesis.
Some tests may fail due to dependency cycles or missing context in test environment.
These issues don't affect actual deployments but indicate tests need more setup.
"""

import json

import aws_cdk as cdk
import aws_cdk.assertions as assertions
import pytest

from openemr_ecs.constants import StackConstants
from openemr_ecs.stack import OpenemrEcsStack

# Import fixtures from conftest.py
pytest_plugins: list[str] = []

# Mark all stack tests as integration tests (require full stack setup)
pytestmark = pytest.mark.integration


def _openemr_task_images(template):
    images = []
    for task_definition in template.find_resources("AWS::ECS::TaskDefinition").values():
        properties = task_definition.get("Properties", {})
        architecture = properties.get("RuntimePlatform", {}).get("CpuArchitecture")
        for container in properties.get("ContainerDefinitions", []):
            image = container.get("Image")
            if isinstance(image, str) and image.startswith("openemr/openemr:"):
                images.append((architecture, image))
    return images


def _expected_openemr_image():
    return f"openemr/openemr:{StackConstants.OPENEMR_VERSION}@{StackConstants.OPENEMR_ARM64_DIGEST}"


def test_rds_cluster_created(template):
    """Test that RDS Aurora cluster is created."""
    rds_clusters = template.find_resources("AWS::RDS::DBCluster")
    assert rds_clusters, "Expected an Aurora DB cluster to be defined"


def test_load_balancer_created(template):
    """Test that Application Load Balancer is created."""
    load_balancers = template.find_resources("AWS::ElasticLoadBalancingV2::LoadBalancer")
    assert load_balancers, "Expected an Application Load Balancer to be defined"


def test_ecs_cluster_created(template):
    """Test that ECS cluster is created."""
    ecs_clusters = template.find_resources("AWS::ECS::Cluster")
    assert ecs_clusters, "Expected an ECS cluster to be defined"


def test_access_log_bucket_encrypted(template):
    """Test that S3 buckets for ALB logs are encrypted."""
    buckets = template.find_resources("AWS::S3::Bucket")
    assert buckets, "Expected S3 buckets to be defined"

    encrypted_buckets = [props for props in buckets.values() if props.get("Properties", {}).get("BucketEncryption")]
    assert encrypted_buckets, "Expected at least one encrypted bucket for ALB access logs"


def test_stack_version_output(template):
    """Test that stack version is included in outputs."""
    template.has_output("StackVersion", {})


def test_default_openemr_tasks_use_immutable_arm64_image(template):
    """The service and one-time setup task use the same immutable ARM64 image."""
    images = _openemr_task_images(template)

    assert len(images) == 2
    assert set(images) == {("ARM64", _expected_openemr_image())}


def test_analytics_openemr_task_uses_immutable_arm64_image(minimal_context):
    """Enabling analytics adds one more task pinned to the immutable ARM64 image."""
    app = cdk.App(
        context={
            **minimal_context,
            "create_serverless_analytics_environment": True,
        }
    )
    stack = OpenemrEcsStack(
        app,
        "OpenemrAnalyticsImageTest",
        env=cdk.Environment(account="123456789012", region="us-west-2"),
    )
    template = assertions.Template.from_stack(stack)
    images = _openemr_task_images(template)

    assert len(images) == 3
    assert set(images) == {("ARM64", _expected_openemr_image())}


_IMPORT_OUTPUTS = {
    "DatabaseClusterArn",
    "OpenEMRImportDatabaseSecurityGroupId",
    "OpenEMRImportEfsAccessPointId",
    "OpenEMRImportEfsSecurityGroupId",
    "OpenEMRImportSecurityGroupId",
    "OpenEMRImportStagingKmsKeyArn",
    "OpenEMRImportStagingBucketName",
    "OpenEMRImportTargetMode",
    "OpenEMRImportTaskDefinitionArn",
    "OpenEMRVersion",
    "PrivateSubnetIds",
}
_ABSENT = object()


def _synthesize_import_boundary(
    minimal_context: dict[str, object],
    import_target: object = _ABSENT,
) -> dict[str, object]:
    context = {
        **minimal_context,
        "openemr_resource_suffix": "importboundary",
    }
    if import_target is not _ABSENT:
        context["openemr_import_target"] = import_target
    app = cdk.App(context=context)
    stack = OpenemrEcsStack(
        app,
        "ImportBoundaryStack",
        env=cdk.Environment(account="123456789012", region="us-west-2"),
    )
    return assertions.Template.from_stack(stack).to_json()


def test_import_resources_are_absent_when_context_is_missing_or_false(
    minimal_context: dict[str, object],
) -> None:
    """Missing and false context synthesize the exact same normal stack."""

    missing = _synthesize_import_boundary(minimal_context)
    disabled = _synthesize_import_boundary(minimal_context, False)

    assert missing == disabled
    assert _IMPORT_OUTPUTS.isdisjoint(missing.get("Outputs", {}))
    rendered = json.dumps(missing, sort_keys=True)
    for import_marker in (
        "OpenEMRImport",
        "openemr-import",
        "import-staging-access/",
        "ExpireImportSource",
        "DenyImportObjectsWithoutExplicitKmsEncryption",
    ):
        assert import_marker not in rendered


def test_import_target_context_synthesizes_complete_guarded_feature(
    minimal_context: dict[str, object],
) -> None:
    """True context adds every import-only resource, grant, and output."""

    normal = _synthesize_import_boundary(minimal_context, False)
    synthesized = _synthesize_import_boundary(minimal_context, True)
    normal_resources = normal["Resources"]
    import_resources = synthesized["Resources"]
    assert isinstance(normal_resources, dict)
    assert isinstance(import_resources, dict)
    assert normal_resources.keys() <= import_resources.keys()
    changed_existing_types = sorted(
        normal_resources[logical_id]["Type"]
        for logical_id in normal_resources.keys() & import_resources.keys()
        if normal_resources[logical_id] != import_resources[logical_id]
    )
    assert changed_existing_types == ["AWS::KMS::Key", "AWS::S3::Bucket"]
    added_types = sorted(
        import_resources[logical_id]["Type"] for logical_id in import_resources.keys() - normal_resources.keys()
    )
    assert added_types == [
        "AWS::EC2::SecurityGroup",
        "AWS::EC2::SecurityGroupEgress",
        "AWS::EC2::SecurityGroupEgress",
        "AWS::EC2::SecurityGroupIngress",
        "AWS::EC2::SecurityGroupIngress",
        "AWS::ECS::TaskDefinition",
        "AWS::EFS::AccessPoint",
        "AWS::IAM::Policy",
        "AWS::IAM::Policy",
        "AWS::IAM::Role",
        "AWS::IAM::Role",
        "AWS::S3::Bucket",
        "AWS::S3::BucketPolicy",
        "Custom::S3AutoDeleteObjects",
    ]

    template = assertions.Template.from_json(synthesized)
    task_definitions = template.find_resources("AWS::ECS::TaskDefinition")
    import_tasks = [
        resource
        for resource in task_definitions.values()
        if any(
            container.get("Name") == "openemr-import"
            for container in resource.get("Properties", {}).get("ContainerDefinitions", [])
        )
    ]
    assert len(import_tasks) == 1
    task = import_tasks[0]["Properties"]
    assert task["Cpu"] == "1024"
    assert task["Memory"] == "2048"
    assert task["EphemeralStorage"]["SizeInGiB"] == 50
    assert task["RuntimePlatform"]["CpuArchitecture"] == "ARM64"
    volume = task["Volumes"][0]["EFSVolumeConfiguration"]
    assert volume["TransitEncryption"] == "ENABLED"
    assert volume["AuthorizationConfig"]["IAM"] == "ENABLED"
    assert "AccessPointId" in volume["AuthorizationConfig"]

    import_container = next(
        container for container in task["ContainerDefinitions"] if container.get("Name") == "openemr-import"
    )
    environment_names = {item["Name"] for item in import_container["Environment"]}
    assert {
        "IMPORT_STAGING_BUCKET_OWNER",
        "IMPORT_STAGING_KMS_KEY_ARN",
        "TARGET_OPENEMR_VERSION",
    }.issubset(environment_names)

    buckets = template.find_resources("AWS::S3::Bucket")
    import_buckets = [
        resource
        for resource in buckets.values()
        if any(
            rule.get("Id") == "ExpireImportSource"
            for rule in resource.get("Properties", {}).get("LifecycleConfiguration", {}).get("Rules", [])
        )
    ]
    assert len(import_buckets) == 1
    bucket = import_buckets[0]["Properties"]
    assert bucket["VersioningConfiguration"]["Status"] == "Enabled"
    rules = {rule["Id"]: rule for rule in bucket["LifecycleConfiguration"]["Rules"]}
    assert rules["ExpireImportSource"]["ExpirationInDays"] == 1
    assert rules["ExpireImportEvidence"]["ExpirationInDays"] == 30

    assert len(template.find_resources("AWS::EFS::AccessPoint")) >= 1
    policies = template.find_resources("AWS::IAM::Policy")
    rendered_policies = json.dumps(policies, sort_keys=True)
    assert "s3:GetObject" in rendered_policies
    assert "s3:PutObject" in rendered_policies
    assert "s3:DeleteObject" not in rendered_policies
    assert "s3:ListBucket" not in rendered_policies
    assert "elasticfilesystem:ClientRootAccess" in rendered_policies
    assert "secretsmanager:GetSecretValue" in rendered_policies

    security_groups = template.find_resources("AWS::EC2::SecurityGroup")
    import_groups = [
        resource
        for resource in security_groups.values()
        if resource.get("Properties", {}).get("GroupDescription")
        == "No-ingress security group for guarded OpenEMR import tasks"
    ]
    assert len(import_groups) == 1
    import_group = import_groups[0]["Properties"]
    assert not import_group.get("SecurityGroupIngress")
    assert {
        (
            rule.get("IpProtocol"),
            rule.get("FromPort"),
            rule.get("ToPort"),
            rule.get("CidrIp"),
        )
        for rule in import_group.get("SecurityGroupEgress", [])
    } == {("tcp", 443, 443, "0.0.0.0/0")}
    guarded_egress = [
        resource["Properties"]
        for resource in template.find_resources("AWS::EC2::SecurityGroupEgress").values()
        if "guarded import tasks" in resource.get("Properties", {}).get("Description", "")
    ]
    guarded_ingress = [
        resource["Properties"]
        for resource in template.find_resources("AWS::EC2::SecurityGroupIngress").values()
        if "guarded import tasks" in resource.get("Properties", {}).get("Description", "")
    ]
    assert {rule["FromPort"] for rule in guarded_egress} == {2049, 3306}
    assert {rule["FromPort"] for rule in guarded_ingress} == {2049, 3306}

    assert _IMPORT_OUTPUTS.issubset(synthesized.get("Outputs", {}))
    template.has_output("OpenEMRImportTargetMode", {"Value": "fresh-target-only"})
