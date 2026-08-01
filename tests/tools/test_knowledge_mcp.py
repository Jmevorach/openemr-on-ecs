"""Security and protocol tests for the local repository knowledge server."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from pathlib import Path

import boto3
import pytest
import requests
from fastmcp import Client

from tools.knowledge_mcp.knowledge import KnowledgeError, RepositoryKnowledge
from tools.knowledge_mcp.server import create_server


@pytest.fixture
def knowledge_root(tmp_path: Path) -> Path:
    """Create a small synthetic repository with no real operational data."""

    (tmp_path / "openemr_ecs").mkdir()
    (tmp_path / "openemr_ecs" / "constants.py").write_text(
        "class StackConstants:\n" '    OPENEMR_VERSION = "8.2.0"\n' '    EMR_SERVERLESS_RELEASE_LABEL = "emr-7.13.0"\n',
        encoding="utf-8",
    )
    (tmp_path / "tools" / "credential-rotation").mkdir(parents=True)
    (tmp_path / "scripts" / "backup-tui").mkdir(parents=True)
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "docs").mkdir()
    (tmp_path / "VERSION").write_text("9.9.9\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("requests==2.34.2\n", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("pytest>=9\n", encoding="utf-8")
    (tmp_path / "tools" / "credential-rotation" / "requirements.txt").write_text(
        "boto3>=1\n",
        encoding="utf-8",
    )
    (tmp_path / "cdk.json").write_text(
        json.dumps(
            {
                "app": "python3 app.py",
                "context": {
                    "enable_monitoring_alarms": False,
                    "password": "must-not-leak",
                    "certificate_arn": (
                        "arn:aws:acm:us-east-1:123456789012:" "certificate/00000000-0000-0000-0000-000000000000"
                    ),
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "# Synthetic OpenEMR\n\nSecure resilient healthcare deployment.\n",
        encoding="utf-8",
    )
    (tmp_path / "ARCHITECTURE.md").write_text(
        "# Architecture\n\n## Aurora database\n\nPrivate encrypted storage.\n",
        encoding="utf-8",
    )
    (tmp_path / "docs" / "guide.md").write_text(
        "# Credential rotation\n\nRotate credentials with explicit approval.\n"
        "password = should-not-leak\n"
        "DB_PASSWORD = prefixed-secret-must-not-leak\n"
        "key = AKIAABCDEFGHIJKLMNOP\n"
        '{"password":"inline-must-not-leak","api_key":"also-private",'
        '"source":"https://user:pass@example.test/archive?token=query-secret"}\n',
        encoding="utf-8",
    )
    return tmp_path


def test_overview_architecture_topics_and_search(knowledge_root: Path) -> None:
    knowledge = RepositoryKnowledge(knowledge_root)

    assert knowledge.overview()["version"] == "9.9.9"
    assert knowledge.architecture()["data_services"]["database"].startswith("Aurora")
    assert knowledge.topic("database")["topic"] == "aurora"
    result = knowledge.search("credential rotation", limit=3)
    assert result[0]["path"] == "docs/guide.md"
    assert "Credential rotation" in result[0]["excerpt"]


def test_safe_read_is_bounded_and_redacted(knowledge_root: Path) -> None:
    knowledge = RepositoryKnowledge(knowledge_root)

    result = knowledge.read_file("docs/guide.md", start_line=1, max_lines=10)

    assert result["total_lines"] == 7
    assert "should-not-leak" not in result["content"]
    assert "prefixed-secret-must-not-leak" not in result["content"]
    assert "AKIAABCDEFGHIJKLMNOP" not in result["content"]
    assert "inline-must-not-leak" not in result["content"]
    assert "also-private" not in result["content"]
    assert "user:pass" not in result["content"]
    assert "query-secret" not in result["content"]
    assert "<redacted>" in result["content"]


def test_configuration_and_versions_are_offline_and_redacted(knowledge_root: Path) -> None:
    knowledge = RepositoryKnowledge(knowledge_root)

    configuration = knowledge.configuration()
    versions = knowledge.versions()

    serialized = json.dumps(configuration)
    assert "must-not-leak" not in serialized
    assert "123456789012" not in serialized
    assert versions["online_lookup"] is False
    assert any(item["name"] == "requests" for item in versions["components"])


def test_curated_sources_and_commands_match_current_tools() -> None:
    knowledge = RepositoryKnowledge()

    assert "LIVE-E2E.md" in knowledge.topic("live-e2e")["sources"]
    assert "docs/deployment-timing.md" in knowledge.topic("timings")["sources"]
    assert "IMPORTING-OPENEMR.md" in knowledge.topic("imports")["sources"]
    assert knowledge.topic("mcp")["topic"] == "knowledge-mcp"
    assert "KNOWLEDGE-MCP.md" in knowledge.topic("knowledge-mcp")["sources"]
    assert "KNOWLEDGE-MCP.md" in knowledge.overview()["primary_guides"]
    commands = {item["purpose"]: item["command"] for item in knowledge.operational_commands()}
    assert "inspect PATH" in commands["Inspect import source"]
    assert "plan inspection.json" in commands["Plan import"]
    assert "--approved-account ACCOUNT" in commands["Live E2E preflight"]
    assert "--preflight PREFLIGHT.json" in commands["Live E2E run"]


def test_path_traversal_symlink_secrets_and_size_are_rejected(
    knowledge_root: Path,
    tmp_path: Path,
) -> None:
    knowledge = RepositoryKnowledge(knowledge_root)
    outside = tmp_path.parent / "outside-mcp-test.md"
    outside.write_text("outside\n", encoding="utf-8")
    (knowledge_root / "docs" / "escape.md").symlink_to(outside)
    (knowledge_root / "docs" / "internal-alias.md").symlink_to("../README.md")
    (knowledge_root / ".env").write_text("TOKEN=secret\n", encoding="utf-8")
    (knowledge_root / "credentials.txt").write_text("secret\n", encoding="utf-8")
    (knowledge_root / "docs" / "large.md").write_text(
        "x" * 256_001,
        encoding="utf-8",
    )

    for path in (
        "../outside-mcp-test.md",
        str(outside),
        "docs/escape.md",
        "docs/internal-alias.md",
        ".env",
        "credentials.txt",
        "docs/large.md",
    ):
        with pytest.raises(KnowledgeError):
            knowledge.read_file(path)


def test_limits_and_unknown_topics_return_structured_errors(
    knowledge_root: Path,
) -> None:
    knowledge = RepositoryKnowledge(knowledge_root)

    with pytest.raises(KnowledgeError, match="Query length"):
        knowledge.search("x")
    with pytest.raises(KnowledgeError, match="Result limit"):
        knowledge.search("architecture", limit=21)
    with pytest.raises(KnowledgeError, match="max_lines"):
        knowledge.read_file("README.md", max_lines=201)
    with pytest.raises(KnowledgeError, match="Unknown topic"):
        knowledge.topic("not-a-topic")


def test_all_knowledge_operations_leave_repository_unchanged(
    knowledge_root: Path,
) -> None:
    knowledge = RepositoryKnowledge(knowledge_root)
    before = {
        path.relative_to(knowledge_root).as_posix(): path.read_bytes()
        for path in knowledge_root.rglob("*")
        if path.is_file()
    }

    knowledge.overview()
    knowledge.architecture()
    knowledge.topic("configuration")
    knowledge.search("OpenEMR")
    knowledge.read_file("README.md")
    knowledge.configuration()
    knowledge.versions()
    knowledge.operational_commands()

    after = {
        path.relative_to(knowledge_root).as_posix(): path.read_bytes()
        for path in knowledge_root.rglob("*")
        if path.is_file()
    }
    assert after == before


def test_normal_retrieval_uses_no_network_aws_or_subprocess(
    knowledge_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("external access is forbidden")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(requests.sessions.Session, "request", forbidden)
    monkeypatch.setattr(boto3, "client", forbidden)
    knowledge = RepositoryKnowledge(knowledge_root)

    knowledge.overview()
    knowledge.architecture()
    knowledge.topic("backup")
    knowledge.search("OpenEMR")
    knowledge.read_file("README.md")
    knowledge.configuration()
    knowledge.versions()
    knowledge.operational_commands()


def test_version_inventory_does_not_scan_denied_state_directories(
    knowledge_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    denied = knowledge_root / ".live-e2e"
    denied.mkdir()
    denied_file = denied / "private-state.json"
    denied_file.write_text('{"password":"must-not-be-read"}\n', encoding="utf-8")
    original_read_text = Path.read_text

    def guarded_read_text(
        path: Path,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        if path == denied_file:
            raise AssertionError("denied state file was read")
        return original_read_text(path, encoding=encoding, errors=errors)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)

    RepositoryKnowledge(knowledge_root).versions()


def test_fastmcp_tools_resources_and_read_only_annotations(
    knowledge_root: Path,
) -> None:
    async def exercise_server() -> None:
        async with Client(create_server(knowledge_root)) as client:
            tools = await client.list_tools()
            resources = await client.list_resources()
            overview = await client.call_tool("project_overview", {})
            topic = await client.call_tool("get_topic", {"topic": "efs"})

            assert len(tools) == 8
            assert all(tool.annotations and tool.annotations.readOnlyHint for tool in tools)
            assert all(tool.annotations and tool.annotations.openWorldHint is False for tool in tools)
            assert {str(resource.uri) for resource in resources} == {
                "openemr://architecture",
                "openemr://overview",
            }
            assert overview.data["version"] == "9.9.9"
            assert topic.data["topic"] == "efs"

    asyncio.run(exercise_server())
