"""Unit tests for OpenEMR ECS CDK stack.

Note: These tests are integration-level tests that require full stack synthesis.
Some tests may fail due to dependency cycles or missing context in test environment.
These issues don't affect actual deployments but indicate tests need more setup.
"""

import aws_cdk as cdk
import aws_cdk.assertions as assertions
import pytest

from openemr_ecs.stack import OpenemrEcsStack

# Import fixtures from conftest.py
pytest_plugins: list[str] = []

# Mark all stack tests as integration tests (require full stack setup)
pytestmark = pytest.mark.integration


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


def test_dormant_import_task_is_private_arm64_and_uses_efs(template):
    """Import support is defined but no scheduled or service execution is created."""
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
    properties = import_tasks[0]["Properties"]
    assert properties["Cpu"] == "1024"
    assert properties["Memory"] == "2048"
    assert properties["EphemeralStorage"]["SizeInGiB"] == 50
    assert properties["RuntimePlatform"]["CpuArchitecture"] == "ARM64"
    volume = properties["Volumes"][0]["EFSVolumeConfiguration"]
    assert volume["TransitEncryption"] == "ENABLED"
    assert volume["AuthorizationConfig"]["IAM"] == "DISABLED"
    assert "AccessPointId" in volume["AuthorizationConfig"]
    import_container = next(
        container for container in properties["ContainerDefinitions"] if container.get("Name") == "openemr-import"
    )
    environment_names = {item["Name"] for item in import_container["Environment"]}
    assert "IMPORT_STAGING_BUCKET_OWNER" in environment_names
    assert "IMPORT_STAGING_KMS_KEY_ARN" in environment_names


def test_import_staging_bucket_and_outputs_are_guarded(template):
    """Import sources expire quickly while recovery evidence remains available."""
    buckets = template.find_resources("AWS::S3::Bucket")
    import_buckets = [
        resource
        for resource in buckets.values()
        if any(
            rule.get("ExpirationInDays") == 1
            for rule in resource.get("Properties", {}).get("LifecycleConfiguration", {}).get("Rules", [])
        )
    ]

    assert len(import_buckets) == 1
    properties = import_buckets[0]["Properties"]
    assert properties["VersioningConfiguration"]["Status"] == "Enabled"
    lifecycle_rules = {rule["Id"]: rule for rule in properties["LifecycleConfiguration"]["Rules"]}
    assert lifecycle_rules["ExpireImportSource"]["ExpirationInDays"] == 1
    assert lifecycle_rules["ExpireImportSource"]["NoncurrentVersionExpiration"]["NoncurrentDays"] == 1
    assert lifecycle_rules["ExpireImportEvidence"]["ExpirationInDays"] == 30
    encryption = properties["BucketEncryption"]["ServerSideEncryptionConfiguration"]
    assert encryption[0]["ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "aws:kms"
    assert properties["PublicAccessBlockConfiguration"] == {
        "BlockPublicAcls": True,
        "BlockPublicPolicy": True,
        "IgnorePublicAcls": True,
        "RestrictPublicBuckets": True,
    }
    policies = template.find_resources("AWS::S3::BucketPolicy")
    statement_ids = {
        statement.get("Sid")
        for policy in policies.values()
        for statement in policy.get("Properties", {}).get("PolicyDocument", {}).get("Statement", [])
    }
    assert "DenyImportObjectsWithoutExplicitKmsEncryption" in statement_ids
    assert "DenyImportObjectsEncryptedWithAnotherKey" in statement_ids
    for output in (
        "DatabaseClusterArn",
        "OpenEMRImportSecurityGroupId",
        "OpenEMRImportStagingKmsKeyArn",
        "OpenEMRImportStagingBucketName",
        "OpenEMRImportTargetMode",
        "OpenEMRImportTaskDefinitionArn",
        "OpenEMRVersion",
        "PrivateSubnetIds",
    ):
        template.has_output(output, {})
    template.has_output("OpenEMRImportTargetMode", {"Value": "disabled"})


def test_live_e2e_context_is_tagged_owned_and_database_is_disposable(minimal_context):
    """E2E cleanup policy is explicit and cannot alter normal stack defaults."""
    run_id = "e2e-unit-test"
    app = cdk.App(
        context={
            **minimal_context,
            "live_e2e_availability_zones": '["us-west-2a","us-west-2b"]',
            "live_e2e_run_id": run_id,
            "openemr_resource_suffix": "e2eunit1234",
            "openemr_service_fargate_maximum_capacity": "1",
            "openemr_service_fargate_minimum_capacity": "1",
            "rds_deletion_protection": "true",
        }
    )
    stack = OpenemrEcsStack(
        app,
        "OpenemrLiveE2E-e2e-unit-test",
        env=cdk.Environment(account="123456789012", region="us-west-2"),
    )
    synthesized = assertions.Template.from_stack(stack).to_json()

    clusters = [resource for resource in synthesized["Resources"].values() if resource["Type"] == "AWS::RDS::DBCluster"]
    assert len(clusters) == 1
    assert clusters[0]["Properties"]["DeletionProtection"] is False
    assert clusters[0]["DeletionPolicy"] == "Delete"
    assert clusters[0]["UpdateReplacePolicy"] == "Delete"
    load_balancers = [
        resource
        for resource in synthesized["Resources"].values()
        if resource["Type"] == "AWS::ElasticLoadBalancingV2::LoadBalancer"
    ]
    assert len(load_balancers) == 1
    attributes = load_balancers[0]["Properties"]["LoadBalancerAttributes"]
    assert {"Key": "deletion_protection.enabled", "Value": "false"} in attributes
    services = [resource for resource in synthesized["Resources"].values() if resource["Type"] == "AWS::ECS::Service"]
    assert len(services) == 1
    assert services[0]["Properties"]["DesiredCount"] == 1
    log_groups = [
        resource for resource in synthesized["Resources"].values() if resource["Type"] == "AWS::Logs::LogGroup"
    ]
    assert log_groups
    assert all(resource["DeletionPolicy"] == "Delete" for resource in log_groups)
    assert all(resource["UpdateReplacePolicy"] == "Delete" for resource in log_groups)
    parameters = [
        resource for resource in synthesized["Resources"].values() if resource["Type"] == "AWS::SSM::Parameter"
    ]
    assert parameters
    assert all(resource["Properties"]["Name"].endswith("_e2eunit1234") for resource in parameters)
    assert synthesized["Outputs"]["LiveE2ERunId"]["Value"] == run_id
    tags = clusters[0]["Properties"]["Tags"]
    assert {"Key": "LiveE2ERunId", "Value": run_id} in tags
    assert {"Key": "Purpose", "Value": "OpenEMRLiveE2E"} in tags
