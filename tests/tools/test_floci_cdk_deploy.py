"""Floci CDK bootstrap/deploy/destroy integration test."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator

import boto3
import pytest

from tools.floci_cdk.deploy import STACK_NAME, run_lifecycle
from tools.live_e2e.emulator import FLOCI_E2E_ENVIRONMENT
from tools.live_e2e.floci_seed import (
    DEFAULT_ACCOUNT_ID,
    DEFAULT_REGION,
    operator_session,
    seed_live_e2e_world,
)

pytestmark = [pytest.mark.integration, pytest.mark.floci, pytest.mark.slow]

FLOCI_IMAGE = os.environ.get("OPENEMR_FLOCI_IMAGE", "floci/floci:1.6.0")
REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def floci_container() -> Iterator[Any]:
    pytest.importorskip("docker")
    try:
        from floci import FlociContainer
    except ImportError as exc:  # pragma: no cover
        pytest.skip(f"testcontainers-floci is not installed: {exc}")

    try:
        with (
            FlociContainer(image=FLOCI_IMAGE)
            .with_account_id(DEFAULT_ACCOUNT_ID)
            .with_region(DEFAULT_REGION) as container
        ):
            yield container
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"Floci container could not start: {exc}")


@pytest.fixture(scope="module")
def floci_endpoint(floci_container: Any) -> str:
    return str(floci_container.get_endpoint())


@pytest.fixture(scope="module")
def seeded_world(floci_container: Any, floci_endpoint: str) -> dict[str, str]:
    admin = boto3.Session(
        region_name=floci_container.get_region(),
        aws_access_key_id=floci_container.get_access_key(),
        aws_secret_access_key=floci_container.get_secret_key(),
    )
    return seed_live_e2e_world(
        admin,
        endpoint_url=floci_endpoint,
        account_id=DEFAULT_ACCOUNT_ID,
        region=DEFAULT_REGION,
        include_bootstrap_fixture=False,
    )


def test_floci_cdk_bootstrap_deploy_destroy(
    monkeypatch: pytest.MonkeyPatch,
    floci_endpoint: str,
    seeded_world: dict[str, str],
) -> None:
    """Prove the pinned CDK CLI can bootstrap, deploy, and destroy against Floci."""

    if not (REPO_ROOT / "node_modules" / ".bin" / "cdk").is_file():
        pytest.skip("Pinned CDK CLI missing; run npm ci")

    monkeypatch.setenv(FLOCI_E2E_ENVIRONMENT, "1")
    monkeypatch.setenv("OPENEMR_AWS_ENDPOINT_URL", floci_endpoint)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", seeded_world["aws_access_key_id"])
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", seeded_world["aws_secret_access_key"])

    boot, deployed, destroyed = run_lifecycle(
        endpoint_url=floci_endpoint,
        access_key_id=seeded_world["aws_access_key_id"],
        secret_access_key=seeded_world["aws_secret_access_key"],
        account_id=DEFAULT_ACCOUNT_ID,
        region=DEFAULT_REGION,
        root=REPO_ROOT,
    )
    assert boot.ok
    assert deployed.ok
    assert destroyed.ok

    outputs_path = REPO_ROOT / "tools" / "floci_cdk" / "cdk.out" / "floci-smoke-outputs.json"
    assert outputs_path.is_file()
    outputs = json.loads(outputs_path.read_text(encoding="utf-8"))
    stack_outputs = outputs.get(STACK_NAME) or {}
    assert stack_outputs.get("BucketName")
    assert stack_outputs.get("QueueUrl")

    session = operator_session(
        endpoint_url=floci_endpoint,
        region=DEFAULT_REGION,
        access_key_id=seeded_world["aws_access_key_id"],
        secret_access_key=seeded_world["aws_secret_access_key"],
    )
    cfn = session.client("cloudformation", endpoint_url=floci_endpoint, region_name=DEFAULT_REGION)
    try:
        stacks = cfn.describe_stacks(StackName=STACK_NAME).get("Stacks", [])
    except Exception:
        stacks = []
    if stacks:
        status = str(stacks[0].get("StackStatus", ""))
        assert status in {"DELETE_COMPLETE", "DELETE_IN_PROGRESS"} or "DELETE" in status
