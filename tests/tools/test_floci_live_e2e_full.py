"""Full live E2E runner against Floci: real CDK bootstrap, deploy, validate, destroy."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator

import boto3
import pytest

from tools.floci_cdk.deploy import bootstrap as floci_bootstrap
from tools.live_e2e.aws import LiveE2EAws
from tools.live_e2e.emulator import FLOCI_E2E_ENVIRONMENT
from tools.live_e2e.floci_seed import (
    DEFAULT_ACCOUNT_ID,
    DEFAULT_REGION,
    DEFAULT_ROUTE53_DOMAIN,
    operator_session,
    seed_live_e2e_world,
)
from tools.live_e2e.runner import (
    ACCOUNT_CONFIRMATION,
    APPROVAL_ENVIRONMENT,
    CREATE_CONFIRMATION,
    DESTROY_CONFIRMATION,
    ZONE_CONFIRMATION,
    LiveE2ERunner,
    stack_name,
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
        container_builder = (
            FlociContainer(image=FLOCI_IMAGE).with_account_id(DEFAULT_ACCOUNT_ID).with_region(DEFAULT_REGION)
        )
        if hasattr(container_builder, "with_dedicated_network"):
            container_builder = container_builder.with_dedicated_network()
        with container_builder as container:
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
    world = seed_live_e2e_world(
        admin,
        endpoint_url=floci_endpoint,
        account_id=DEFAULT_ACCOUNT_ID,
        region=DEFAULT_REGION,
        route53_domain=DEFAULT_ROUTE53_DOMAIN,
        include_bootstrap_fixture=False,
    )
    os.environ[FLOCI_E2E_ENVIRONMENT] = "1"
    os.environ["OPENEMR_AWS_ENDPOINT_URL"] = floci_endpoint
    os.environ["AWS_ACCESS_KEY_ID"] = world["aws_access_key_id"]
    os.environ["AWS_SECRET_ACCESS_KEY"] = world["aws_secret_access_key"]
    boot = floci_bootstrap(
        endpoint_url=floci_endpoint,
        access_key_id=world["aws_access_key_id"],
        secret_access_key=world["aws_secret_access_key"],
        account_id=DEFAULT_ACCOUNT_ID,
        region=DEFAULT_REGION,
        root=REPO_ROOT,
    )
    if not boot.ok:
        pytest.fail(f"Floci CDK bootstrap failed:\n{boot.stdout}\n{boot.stderr}")
    return world


def test_floci_full_live_e2e_runner(
    monkeypatch: pytest.MonkeyPatch,
    floci_endpoint: str,
    seeded_world: dict[str, str],
) -> None:
    """Run the guarded live E2E runner end-to-end against Floci with real CDK deploy/destroy."""

    if not (REPO_ROOT / "node_modules" / ".bin" / "cdk").is_file():
        pytest.skip("Pinned CDK CLI missing; run npm ci")

    monkeypatch.setenv(FLOCI_E2E_ENVIRONMENT, "1")
    monkeypatch.setenv("OPENEMR_AWS_ENDPOINT_URL", floci_endpoint)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", seeded_world["aws_access_key_id"])
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", seeded_world["aws_secret_access_key"])
    monkeypatch.setenv("AWS_DEFAULT_REGION", DEFAULT_REGION)
    monkeypatch.setenv("CI", "true")

    run_id = "e2e-floci-full"
    name = stack_name(run_id)

    def aws_factory(**kwargs: Any) -> LiveE2EAws:
        session = operator_session(
            endpoint_url=floci_endpoint,
            region=DEFAULT_REGION,
            access_key_id=seeded_world["aws_access_key_id"],
            secret_access_key=seeded_world["aws_secret_access_key"],
        )
        return LiveE2EAws(
            region=str(kwargs.get("region", DEFAULT_REGION)),
            session=session,
            endpoint_url=floci_endpoint,
            emulated=True,
        )

    runner = LiveE2ERunner(root=REPO_ROOT, aws_factory=aws_factory)
    # CI worktrees are clean; keep local dirty trees from failing this suite.
    monkeypatch.setattr(runner, "_git_commit_and_clean", lambda: "b" * 40)
    monkeypatch.setattr(
        runner,
        "_git_branch_and_repository",
        lambda: ("cursor/maintenance-import-mcp-e2e", "Jmevorach/openemr-on-ecs"),
    )

    preflight_path = runner.preflight(
        approved_account=DEFAULT_ACCOUNT_ID,
        region=DEFAULT_REGION,
        route53_domain=seeded_world["route53_domain"],
        allowed_ipv4_cidr="8.8.8.8/32",
        profile="default",
        aws_profile=None,
        cdk_command="cdk",
        bootstrap_stack_name="CDKToolkit",
        confirm_dedicated_zone=ZONE_CONFIRMATION,
        confirm_non_production_account=ACCOUNT_CONFIRMATION,
        run_id=run_id,
        require_tty=False,
    )

    monkeypatch.setenv(APPROVAL_ENVIRONMENT, run_id)
    result = runner.run(
        preflight_path=preflight_path,
        approved_account=DEFAULT_ACCOUNT_ID,
        confirm_create=CREATE_CONFIRMATION,
        confirm_destroy=DESTROY_CONFIRMATION,
        confirm_costs=True,
        require_tty=False,
        deploy_timeout_seconds=45 * 60,
        readiness_timeout_seconds=10 * 60,
        cleanup_timeout_seconds=30 * 60,
        poll_seconds=5,
    )

    assert result.cleanup_status in {
        "complete",
        "stack-deleted-with-expected-residuals",
        "not-required",
    }, result.cleanup_status
    assert result.status == "passed", (
        f"Floci live E2E failed: status={result.status} "
        f"failure_phase={result.failure_phase} cleanup={result.cleanup_status}"
    )

    adapter = aws_factory(region=DEFAULT_REGION)
    assert adapter.describe_stack(name) is None
