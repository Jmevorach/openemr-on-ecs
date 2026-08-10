"""Unit tests for Floci runtime image helpers (no Docker required)."""

from __future__ import annotations

from openemr_ecs.constants import StackConstants
from tools.live_e2e.floci_images import aurora_mysql_engine_version, aurora_mysql_floci_image


def test_aurora_mysql_engine_version_tracks_stack_constant() -> None:
    assert aurora_mysql_engine_version() == StackConstants.AURORA_MYSQL_ENGINE_VERSION.aurora_mysql_full_version


def test_aurora_mysql_floci_image_matches_stack_engine_version_tag() -> None:
    version = StackConstants.AURORA_MYSQL_ENGINE_VERSION.aurora_mysql_full_version
    assert aurora_mysql_floci_image() == f"mysql:{version}"


def test_aurora_mysql_floci_image_accepts_explicit_engine_version() -> None:
    assert aurora_mysql_floci_image("8.0.mysql_aurora.9.9.9") == "mysql:8.0.mysql_aurora.9.9.9"
