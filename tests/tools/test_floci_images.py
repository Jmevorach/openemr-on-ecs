"""Unit tests for Floci runtime image helpers (no Docker required)."""

from __future__ import annotations

from tools.live_e2e.floci_images import aurora_mysql_floci_image


def test_aurora_mysql_floci_image_matches_engine_version_tag() -> None:
    assert aurora_mysql_floci_image("8.0.mysql_aurora.3.12.0") == "mysql:8.0.mysql_aurora.3.12.0"
