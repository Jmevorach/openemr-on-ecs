"""Unit tests for OpenEMR ECS CDK stack.

Note: These tests are integration-level tests that require full stack synthesis.
Some tests may fail due to dependency cycles or missing context in test environment.
These issues don't affect actual deployments but indicate tests need more setup.
"""

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
