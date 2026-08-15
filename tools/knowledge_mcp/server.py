"""Read-only FastMCP server for local OpenEMR on ECS knowledge."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from .knowledge import RepositoryKnowledge

_READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}


def create_server(root: Path | None = None) -> FastMCP:
    """Create an offline server bound to one repository root."""

    knowledge = RepositoryKnowledge(root)
    server = FastMCP(
        "OpenEMR on ECS Knowledge",
        instructions=(
            "Read-only, offline, bounded repository knowledge. This server uses local files only. "
            "It cannot execute commands, write files, access AWS, or make network requests."
        ),
    )

    @server.tool(annotations=_READ_ONLY)
    def project_overview() -> dict[str, Any]:
        """Return project purpose, version, entry points, and primary guides."""

        return knowledge.overview()

    @server.tool(annotations=_READ_ONLY)
    def architecture_map() -> dict[str, Any]:
        """Return the request path, data services, and CDK construct map."""

        return knowledge.architecture()

    @server.tool(annotations=_READ_ONLY)
    def get_topic(topic: str) -> dict[str, Any]:
        """Retrieve a curated repository topic and its local source files."""

        return knowledge.topic(topic)

    @server.tool(annotations=_READ_ONLY)
    def search_repository(query: str, limit: int = 8) -> list[dict[str, Any]]:
        """Run a bounded ranked search over approved local text files."""

        return knowledge.search(query, limit=limit)

    @server.tool(annotations=_READ_ONLY)
    def read_repository_file(
        path: str,
        start_line: int = 1,
        max_lines: int = 100,
    ) -> dict[str, Any]:
        """Read a bounded line range from a policy-approved repository file."""

        return knowledge.read_file(path, start_line=start_line, max_lines=max_lines)

    @server.tool(annotations=_READ_ONLY)
    def documentation_index() -> dict[str, Any]:
        """List all searchable documentation and validated curated sources."""

        return knowledge.documentation_index()

    @server.tool(annotations=_READ_ONLY)
    def version_inventory(categories: list[str] | None = None) -> dict[str, Any]:
        """Return declared versions without installed-package or network lookups."""

        return knowledge.versions(categories)

    @server.tool(annotations=_READ_ONLY)
    def configuration_reference() -> dict[str, Any]:
        """Return CDK context keys and redacted local defaults."""

        return knowledge.configuration()

    @server.tool(annotations=_READ_ONLY)
    def discover_operational_commands() -> list[dict[str, Any]]:
        """Describe maintainer commands and risk; never execute them."""

        return knowledge.operational_commands()

    @server.resource("openemr://overview", mime_type="application/json")
    def overview_resource() -> str:
        """Expose the project overview as a stable MCP resource."""

        return json.dumps(knowledge.overview(), sort_keys=True)

    @server.resource("openemr://architecture", mime_type="application/json")
    def architecture_resource() -> str:
        """Expose the architecture map as a stable MCP resource."""

        return json.dumps(knowledge.architecture(), sort_keys=True)

    @server.resource("openemr://documentation-index", mime_type="application/json")
    def documentation_index_resource() -> str:
        """Expose the complete searchable documentation index."""

        return json.dumps(knowledge.documentation_index(), sort_keys=True)

    return server


def run_stdio() -> None:
    """Run only the local STDIO transport."""

    create_server().run(transport="stdio")
