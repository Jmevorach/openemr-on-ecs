# Repository Knowledge MCP

The repository includes a local Model Context Protocol (MCP) server that helps
MCP-capable assistants understand OpenEMR on ECS. It exposes curated project
knowledge and bounded repository retrieval without granting operational access.

The server is optional. It is intended for maintainers, contributors, and
reviewers who want grounded answers about this repository.

## Capabilities

The server provides these read-only tools:

- `project_overview` — project purpose, version, entry points, and guides.
- `architecture_map` — request flow, data services, and CDK construct sources.
- `get_topic` — curated summaries and source files for supported topics.
- `search_repository` — bounded, ranked search over approved text files.
- `read_repository_file` — a bounded line range from an approved file.
- `version_inventory` — locally declared versions without online resolution.
- `configuration_reference` — CDK context keys with sensitive defaults redacted.
- `discover_operational_commands` — command and risk descriptions; commands are
  never executed.

It also exposes the `openemr://overview` and `openemr://architecture` JSON
resources.

## Install and run

From the repository root, create the project environment and install both
runtime and development dependencies:

```bash
python3.14 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
```

Start the STDIO server:

```bash
.venv/bin/python -m tools.knowledge_mcp
```

The process communicates through standard input and output, so normally an MCP
client starts it rather than a person running it interactively.

## Configure Cursor

Add this server to `.cursor/mcp.json` for this workspace. The example assumes a
macOS or Linux virtual environment at `.venv`; use the equivalent absolute
Python path on Windows.

```json
{
  "mcpServers": {
    "openemr-on-ecs-knowledge": {
      "type": "stdio",
      "command": "${workspaceFolder}/.venv/bin/python",
      "args": ["-m", "tools.knowledge_mcp"],
      "env": {
        "PYTHONPATH": "${workspaceFolder}"
      }
    }
  }
}
```

Restart Cursor after saving the configuration, then verify the server in
**Settings > Tools & MCP**. See the
[Cursor MCP documentation](https://cursor.com/docs/mcp) for global
configuration and troubleshooting.

Do not add AWS credentials, API keys, or secrets to this server configuration;
the knowledge server does not need them.

## Other MCP clients

Configure a local STDIO server with:

- command: the repository virtual environment's Python executable;
- arguments: `-m tools.knowledge_mcp`; and
- working directory or `PYTHONPATH`: the repository root.

Exact configuration keys vary by client.

## Safety boundaries

The knowledge MCP is deliberately narrower than a general filesystem server:

- It supports only local STDIO transport.
- It has no write, shell, subprocess, AWS, or network tools.
- Every tool is annotated read-only, non-destructive, idempotent, and
  closed-world.
- Reads are limited to approved repository-relative text paths and extensions.
- Path traversal, absolute paths, symlinks, secret-like paths, oversized files,
  oversized line ranges, and unbounded searches are rejected.
- Returned text and configuration values pass through credential, URL user-info,
  and sensitive query-value redaction.
- Operational commands are returned only as documentation with a risk label.

These controls limit the server itself. The MCP client may have other tools and
permissions, so continue to review the client's proposed actions. Read-only MCP
output is not approval to deploy, import, restore, or delete AWS resources.

## Example requests

After connecting the server, ask the client to:

- summarize the request path and identify its source files;
- find the configuration controlling ECS task scaling;
- list declared container, runtime, and toolchain versions;
- explain the guarded import or live E2E workflow;
- retrieve the documented risk level for an operational command.

## Validate the server

Run the focused protocol and security tests:

```bash
.venv/bin/pytest tests/tools/test_knowledge_mcp.py -q
```

The tests exercise all tools and resources in memory and verify read-only
annotations, redaction, path controls, bounded retrieval, and the absence of
network, AWS, or subprocess access during normal retrieval.

## Troubleshooting

- `No module named tools`: launch from the repository root or set
  `PYTHONPATH` to it.
- `No module named fastmcp`: install `requirements-dev.txt` in the Python
  environment used by the client.
- Server not listed: validate `mcp.json`, restart the client, and confirm that
  the configured Python path exists.
- File rejected: use a repository-relative, policy-approved text path. Binary,
  secret-like, symlinked, and oversized files are intentionally unavailable.
