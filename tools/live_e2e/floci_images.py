"""Ensure host Docker images Floci needs for OpenEMR stack resources exist locally.

Floci maps RDS/Aurora ``EngineVersion`` onto a Docker tag. For example,
``8.0.mysql_aurora.3.12.0`` becomes ``mysql:8.0.mysql_aurora.3.12.0``, which is
not published on Docker Hub. Pull the MySQL community image and retag it so
Floci's Docker client can start the cluster without a registry 404.

The Aurora engine version is taken from
``StackConstants.AURORA_MYSQL_ENGINE_VERSION`` so image prep stays aligned with
the CDK stack when that constant is bumped.
"""

from __future__ import annotations

import os
from typing import Sequence

from openemr_ecs.constants import StackConstants
from tools._shared import ToolError

DEFAULT_MYSQL_SOURCE_IMAGE = os.environ.get("OPENEMR_FLOCI_MYSQL_SOURCE_IMAGE", "mysql:8.0")
DEFAULT_VALKEY_IMAGE = os.environ.get("OPENEMR_FLOCI_VALKEY_IMAGE", "valkey/valkey:8")


def aurora_mysql_engine_version() -> str:
    """Return the stack's Aurora MySQL full engine version string."""

    version = StackConstants.AURORA_MYSQL_ENGINE_VERSION.aurora_mysql_full_version
    if not isinstance(version, str) or not version.strip():
        raise ToolError("StackConstants.AURORA_MYSQL_ENGINE_VERSION has no aurora_mysql_full_version")
    return version.strip()


def aurora_mysql_floci_image(engine_version: str | None = None) -> str:
    """Return the Docker image reference Floci will request for an Aurora engine version."""

    return f"mysql:{(engine_version or aurora_mysql_engine_version()).strip()}"


def ensure_floci_runtime_images(
    *,
    engine_version: str | None = None,
    mysql_source_image: str = DEFAULT_MYSQL_SOURCE_IMAGE,
    extra_images: Sequence[str] = (DEFAULT_VALKEY_IMAGE,),
) -> tuple[str, ...]:
    """Pull/tag images on the host Docker daemon used by Floci via the mounted socket."""

    try:
        import docker
    except ImportError as exc:  # pragma: no cover
        raise ToolError("docker Python package is required to prepare Floci runtime images") from exc

    resolved_version = engine_version or aurora_mysql_engine_version()
    client = docker.from_env()
    prepared: list[str] = []
    target = aurora_mysql_floci_image(resolved_version)
    _pull(client, mysql_source_image)
    if target != mysql_source_image:
        source = client.images.get(mysql_source_image)
        repository, _, tag = target.partition(":")
        if not tag:
            raise ToolError(f"Floci Aurora image reference is missing a tag: {target}")
        source.tag(repository=repository, tag=tag)
    prepared.append(target)
    for image in extra_images:
        if not image:
            continue
        _pull(client, image)
        prepared.append(image)
    return tuple(prepared)


def _pull(client: object, image: str) -> None:
    """Pull ``image`` or raise a ToolError with the underlying Docker message."""

    try:
        client.images.pull(image)  # type: ignore[attr-defined]
    except Exception as exc:  # pragma: no cover - depends on local Docker/network
        raise ToolError(f"Failed to pull Floci runtime image {image}: {exc}") from exc
