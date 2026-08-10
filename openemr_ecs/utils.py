"""Shared utility functions for the OpenEMR CDK stack."""

from typing import Optional


def is_true(val: Optional[str]) -> bool:
    """Check if a context value represents a true boolean.

    Context values from CDK are strings, so we need to normalize them.
    This function handles None, empty strings, and various true representations.

    Args:
        val: The value to check (typically from context.get())

    Returns:
        True if the value represents true, False otherwise
    """
    if val is None:
        return False
    return str(val).lower() == "true"


def get_resource_suffix(context: dict) -> str:
    """Get the resource suffix from context, with a safe default.

    Args:
        context: CDK context dictionary

    Returns:
        The resource suffix string, or 'default' if not provided
    """
    result = context.get("openemr_resource_suffix", "default")
    return str(result) if result is not None else "default"


def s3_auto_delete_objects(context: Optional[dict] = None) -> bool:
    """Return whether S3 buckets should install the AutoDeleteObjects custom resource.

    Floci Lambda custom resources currently fail to join the emulator Docker
    network, so emulated live E2E disables auto-delete and relies on
    RemovalPolicy.DESTROY plus owned-stack cleanup instead.
    """

    if context is None:
        return True
    return not is_true(context.get("live_e2e_emulated"))


def get_ssm_parameter_name(base_name: str, context: dict) -> str:
    """Return an E2E-isolated SSM name without changing production names."""

    if context.get("live_e2e_run_id"):
        return f"{base_name}_{get_resource_suffix(context)}"
    return base_name
