"""Local AWS emulator (Floci) guards and endpoint helpers for live E2E."""

from __future__ import annotations

import os
from urllib.parse import urlparse

from tools._shared import ToolError

FLOCI_E2E_ENVIRONMENT = "OPENEMR_FLOCI_E2E"
AWS_ENDPOINT_ENVIRONMENT = "OPENEMR_AWS_ENDPOINT_URL"
_FALLBACK_ENDPOINT_ENVIRONMENT = "AWS_ENDPOINT_URL"
_LOCAL_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "host.docker.internal",
    "floci",
}


def resolve_emulator_endpoint_url() -> str | None:
    """Return the configured AWS emulator endpoint, if any."""

    for name in (AWS_ENDPOINT_ENVIRONMENT, _FALLBACK_ENDPOINT_ENVIRONMENT):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def is_local_emulator_endpoint(endpoint_url: str) -> bool:
    """Return True when the endpoint clearly targets a local emulator."""

    parsed = urlparse(endpoint_url)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False
    if host in _LOCAL_HOSTS:
        return True
    return host.endswith(".localhost")


def assert_safe_emulator_endpoint(endpoint_url: str | None) -> str:
    """Require a non-empty local emulator endpoint for Floci mode."""

    if not endpoint_url:
        raise ToolError(f"{FLOCI_E2E_ENVIRONMENT} requires {AWS_ENDPOINT_ENVIRONMENT} (or AWS_ENDPOINT_URL)")
    if not is_local_emulator_endpoint(endpoint_url):
        raise ToolError("Floci E2E refuses non-local AWS endpoints")
    host = (urlparse(endpoint_url).hostname or "").lower()
    if "amazonaws.com" in host or host.endswith(".aws"):
        raise ToolError("Floci E2E refuses real AWS endpoints")
    return endpoint_url


def floci_flag_enabled() -> bool:
    """Return True when the explicit Floci E2E environment flag is set."""

    return os.environ.get(FLOCI_E2E_ENVIRONMENT, "").strip().lower() in {"1", "true", "yes", "on"}


def is_floci_e2e_enabled(endpoint_url: str | None = None) -> bool:
    """Return True when Floci-backed live E2E is explicitly enabled and safe."""

    if not floci_flag_enabled():
        return False
    assert_safe_emulator_endpoint(endpoint_url if endpoint_url is not None else resolve_emulator_endpoint_url())
    return True
