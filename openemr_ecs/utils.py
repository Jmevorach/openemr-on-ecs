"""Shared utility functions for the OpenEMR CDK stack."""

import hashlib
import re
from typing import Optional

_SERVERLESS_CACHE_NAME_MAX = 40
_SERVERLESS_CACHE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")


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
    """Build a valid Valkey name without renaming existing valid caches.

    The historical name is retained whenever it already satisfies
    ElastiCache's 40-character limit. Only over-limit or invalid names use a
    deterministic shortened form.
    """

    legacy_name = f"{stack_name.lower()[:20]}-{suffix}-valkey"
    if len(legacy_name) <= _SERVERLESS_CACHE_NAME_MAX and _SERVERLESS_CACHE_NAME_RE.fullmatch(legacy_name):
        return legacy_name

    readable = re.sub(r"[^a-z0-9-]", "", f"{stack_name}-{suffix}".lower()).strip("-")
    if not readable or not readable[0].isalpha():
        readable = f"openemr-{readable}".strip("-")
    digest_input = f"{stack_name}\0{suffix}".encode("utf-8")
    digest = hashlib.sha256(digest_input).hexdigest()[:8]
    trailer = f"-{digest}-valkey"
    prefix = readable[: _SERVERLESS_CACHE_NAME_MAX - len(trailer)].rstrip("-") or "openemr"
    return f"{prefix}{trailer}"
