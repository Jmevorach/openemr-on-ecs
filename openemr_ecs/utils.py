"""Shared utility functions for the OpenEMR CDK stack."""

import os
from typing import Optional
from urllib.parse import urlparse

_FLOCI_FLAG = "OPENEMR_FLOCI_E2E"
_FLOCI_ENDPOINTS = ("OPENEMR_AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL")
_LOCAL_FLOCI_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "host.docker.internal",
    "floci",
}


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


def get_ssm_parameter_name(base_name: str, context: dict) -> str:
    """Return the historical or live-E2E-scoped SSM parameter name."""

    if context.get("live_e2e_run_id"):
        return f"{base_name}_{get_resource_suffix(context)}"
    return base_name


def is_live_e2e_emulated(context: Optional[dict] = None) -> bool:
    """Return True only for an explicitly guarded local Floci synthesis.

    A context value alone is deliberately insufficient: this prevents someone
    from using ``-c live_e2e_emulated=true`` against real AWS to omit resources.
    The live-E2E runner must also set its explicit Floci flag and a local AWS
    endpoint.
    """

    if not context or not is_true(context.get("live_e2e_emulated")):
        return False
    if os.environ.get(_FLOCI_FLAG, "").strip().lower() not in {"1", "true", "yes", "on"}:
        return False
    endpoint = next((os.environ.get(name, "").strip() for name in _FLOCI_ENDPOINTS if os.environ.get(name)), "")
    parsed = urlparse(endpoint)
    host = (parsed.hostname or "").strip().lower()
    if parsed.scheme not in {"http", "https"} or not host:
        return False
    if "amazonaws.com" in host or host.endswith(".aws"):
        return False
    return host in _LOCAL_FLOCI_HOSTS or host.endswith(".localhost")


def s3_auto_delete_objects(context: Optional[dict] = None) -> bool:
    """Disable Lambda-backed S3 deletion only for guarded Floci synthesis."""

    return not is_live_e2e_emulated(context)
