"""Shared utility functions for the OpenEMR CDK stack."""

import re
from typing import Optional

_SERVERLESS_CACHE_NAME_MAX = 40
_SERVERLESS_CACHE_NAME_RE = re.compile(r"[^a-z0-9-]+")


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


def serverless_cache_name(stack_name: str, suffix: str) -> str:
    """Build an ElastiCache Serverless cache name within the 40-character limit.

    Live E2E stack names plus the e2e resource suffix previously produced names
    like ``openemre2e-756cf49f94-e2e29b8e97077-valkey`` (41 chars), which AWS
    rejects. Prefer uniqueness from the suffix, then fill remaining budget with
    a sanitized stack token.
    """

    safe_suffix = _SERVERLESS_CACHE_NAME_RE.sub("", str(suffix).lower()).strip("-") or "default"
    if safe_suffix[0].isdigit():
        safe_suffix = f"e{safe_suffix}"
    trailer = f"-{safe_suffix}-vk"
    if len(trailer) >= _SERVERLESS_CACHE_NAME_MAX:
        # Pathological suffix: keep a letter prefix and truncate hard.
        return f"e{safe_suffix}"[:_SERVERLESS_CACHE_NAME_MAX]

    budget = _SERVERLESS_CACHE_NAME_MAX - len(trailer)
    token = _SERVERLESS_CACHE_NAME_RE.sub("", str(stack_name).lower()).strip("-")
    if not token or not token[0].isalpha():
        token = f"o{token}" if token else "openemr"
    token = token[:budget].strip("-") or "o"
    return f"{token}{trailer}"


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
