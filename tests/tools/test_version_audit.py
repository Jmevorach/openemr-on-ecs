"""Focused tests for the reusable dependency and platform version audit."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import requests

from tools.version_audit import audit
from tools.version_audit.__main__ import EXIT_OK, EXIT_UPDATES, main
from tools.version_audit.inventory import (
    collect_action_declarations,
    collect_go_declarations,
    collect_node_declarations,
    collect_precommit_declarations,
    collect_python_declarations,
    collect_stack_platform_declarations,
    collect_workflow_toolchains,
)
from tools.version_audit.models import AuditReport, Declaration, Finding, Status
from tools.version_audit.render import render_markdown
from tools.version_audit.sources import HttpClient, Resolution, SourceError, VersionSources


def _repository(tmp_path: Path) -> Path:
    (tmp_path / "openemr_ecs").mkdir()
    (tmp_path / ".github" / "workflows").mkdir(parents=True)
    (tmp_path / "scripts" / "backup-tui").mkdir(parents=True)
    (tmp_path / "tools" / "credential-rotation").mkdir(parents=True)
    (tmp_path / "tools" / "openemr-import-worker").mkdir(parents=True)
    (tmp_path / "cdk.json").write_text('{"context": {}}\n', encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "requirements-dev.txt").write_text("", encoding="utf-8")
    (tmp_path / "tools" / "credential-rotation" / "requirements.txt").write_text("", encoding="utf-8")
    (tmp_path / "tools" / "openemr-import-worker" / "requirements.txt").write_text("", encoding="utf-8")
    return tmp_path


def _declaration(**overrides: Any) -> Declaration:
    values: dict[str, Any] = {
        "identifier": "python:demo",
        "name": "demo",
        "category": "python-production",
        "current": "1.0.0",
        "definition": "requirements.txt:1",
        "source_kind": "pypi",
        "constraint": "==1.0.0",
        "metadata": {"normalized_name": "demo"},
    }
    values.update(overrides)
    return Declaration(**values)


def test_python_inventory_parses_pep508_and_deduplicates(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "requirements.txt").write_text(
        "Demo_Pkg[feature]==1.2.3; python_version >= '3.12'\n" "-r extra.txt\n",
        encoding="utf-8",
    )
    (root / "extra.txt").write_text("requests>=2.0,<3\n", encoding="utf-8")
    (root / "requirements-dev.txt").write_text("demo-pkg==1.2.3\n", encoding="utf-8")
    (root / "tools" / "openemr-import-worker" / "requirements.txt").write_text(
        "boto3==1.2.3\n",
        encoding="utf-8",
    )

    declarations = {item.identifier: item for item in collect_python_declarations(root)}

    demo = declarations["python:demo-pkg"]
    assert demo.current == "1.2.3"
    assert demo.category == "python-shared"
    assert demo.metadata["extras"] == ["feature"]
    assert demo.metadata["markers"] == ['python_version >= "3.12"']
    assert declarations["python:requests"].current == "<3,>=2.0"
    assert declarations["python:boto3"].current == "1.2.3"


def test_python_inventory_reports_malformed_requirement(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "requirements.txt").write_text("not a valid !!! requirement\n", encoding="utf-8")

    declarations = collect_python_declarations(root)

    assert declarations[0].source_kind == "inventory-error"
    assert declarations[0].metadata["error"] == "Invalid PEP 508 requirement"


def test_go_inventory_includes_only_direct_modules(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "scripts" / "backup-tui" / "go.mod").write_text(
        "module example.test/tool\n\ngo 1.25\n\nrequire (\n"
        "\texample.test/direct v1.2.3\n"
        "\texample.test/indirect v2.0.0 // indirect\n"
        ")\n",
        encoding="utf-8",
    )

    identifiers = {item.identifier for item in collect_go_declarations(root)}

    assert "toolchain:go" in identifiers
    assert "go:example.test/direct" in identifiers
    assert "go:example.test/indirect" not in identifiers


def test_toolchain_inventory_binds_workflows_manifests_and_dockerfiles(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    workflow = root / ".github" / "workflows" / "ci.yml"
    workflow.write_text(
        'env:\n  PYTHON_VERSION: "3.14"\n  NODE_VERSION: "24"\n  PIP_VERSION: "26.2"\n',
        encoding="utf-8",
    )
    (root / "package.json").write_text(
        '{"engines":{"node":">=24 <25"}}\n',
        encoding="utf-8",
    )
    dockerfile = root / "tools" / "openemr-import-worker" / "Dockerfile"
    dockerfile.write_text(
        "ARG PYTHON_VERSION=3.14\nFROM python:${PYTHON_VERSION}-alpine\n",
        encoding="utf-8",
    )

    declarations = {item.identifier: item for item in collect_workflow_toolchains(root)}

    assert declarations["toolchain:python"].current == "3.14"
    assert "Dockerfile:1" in declarations["toolchain:python"].definition
    assert declarations["toolchain:python"].metadata["conflicting_pins"] is False
    assert declarations["toolchain:node"].current == "24"
    assert "package.json:1" in declarations["toolchain:node"].definition
    assert declarations["toolchain:pip"].current == "26.2"
    assert declarations["toolchain:pip"].source_kind == "pypi"

    dockerfile.write_text(
        "ARG PYTHON_VERSION=3.13\nFROM python:${PYTHON_VERSION}-alpine\n",
        encoding="utf-8",
    )
    declarations = {item.identifier: item for item in collect_workflow_toolchains(root)}
    assert declarations["toolchain:python"].current == "3.13 / 3.14"
    assert declarations["toolchain:python"].metadata["conflicting_pins"] is True


def test_stack_inventory_uses_ast_not_regex(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / "openemr_ecs" / "constants.py").write_text(
        "class StackConstants:\n"
        "    OPENEMR_VERSION = '8.1.1'\n"
        f"    OPENEMR_ARM64_DIGEST = 'sha256:{'a' * 64}'\n"
        "    AURORA_MYSQL_ENGINE_VERSION = rds.AuroraMysqlEngineVersion.VER_3_12_0\n"
        "    LAMBDA_PYTHON_RUNTIME = runtime.PYTHON_3_14\n"
        "    EMR_SERVERLESS_RELEASE_LABEL = 'emr-7.13.0'\n",
        encoding="utf-8",
    )

    declarations = {item.identifier: item for item in collect_stack_platform_declarations(root)}

    assert declarations["container:openemr"].current == "8.1.1"
    assert declarations["container:openemr"].metadata["arm64_digest"] == f"sha256:{'a' * 64}"
    assert declarations["platform:aurora-mysql"].current == "3.12.0"
    assert declarations["platform:lambda-python"].current == "3.14"


def test_actions_inventory_deduplicates_consumers(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / ".github" / "workflows" / "one.yml").write_text(
        "steps:\n  - uses: actions/checkout@v6\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "two.yml").write_text(
        "steps:\n  - uses: actions/checkout@v6\n",
        encoding="utf-8",
    )

    declarations = collect_action_declarations(root)

    assert len(declarations) == 1
    assert declarations[0].current == "v6"
    assert len(declarations[0].consumers) == 1
    assert declarations[0].metadata["immutable_sha_pins"] is False


def test_actions_inventory_reads_version_comment_for_sha_pin(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    sha = "a" * 40
    (root / ".github" / "workflows" / "one.yml").write_text(
        f"steps:\n  - uses: actions/checkout@{sha} # v7.0.1\n",
        encoding="utf-8",
    )

    declaration = collect_action_declarations(root)[0]

    assert declaration.current == "v7.0.1"
    assert declaration.metadata["immutable_sha_pins"] is True
    assert declaration.metadata["revision_labels"] == {sha: "v7.0.1"}


def test_precommit_inventory_pairs_repo_and_revision(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    sha = "c" * 40
    (root / ".pre-commit-config.yaml").write_text(
        "repos:\n"
        "  - repo: https://github.com/psf/black\n"
        f"    rev: {sha} # 25.1.0\n"
        "    hooks:\n"
        "      - id: black\n",
        encoding="utf-8",
    )

    declarations = collect_precommit_declarations(root)

    assert declarations[0].name == "psf/black"
    assert declarations[0].current == "25.1.0"
    assert declarations[0].metadata["revision_labels"] == {sha: "25.1.0"}
    assert declarations[0].metadata["immutable_sha_pins"] is True


def test_node_inventory_uses_lockfile_resolution_and_manifest_constraint(
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    (root / "package.json").write_text(
        '{"private":true,"devDependencies":{"aws-cdk":"^2.1134.0"}}\n',
        encoding="utf-8",
    )
    (root / "package-lock.json").write_text(
        json.dumps(
            {
                "packages": {
                    "": {"devDependencies": {"aws-cdk": "^2.1134.0"}},
                    "node_modules/aws-cdk": {"version": "2.1134.1"},
                }
            }
        ),
        encoding="utf-8",
    )

    declaration = collect_node_declarations(root)[0]

    assert declaration.identifier == "node:aws-cdk"
    assert declaration.current == "2.1134.1"
    assert declaration.constraint == "^2.1134.0"
    assert any("package-lock.json" in consumer for consumer in declaration.consumers)


def test_http_client_converts_timeout_to_source_error(monkeypatch: pytest.MonkeyPatch) -> None:
    client = HttpClient(timeout_seconds=0.1)

    def fail(*args: Any, **kwargs: Any) -> None:
        raise requests.Timeout("slow")

    monkeypatch.setattr(client.session, "get", fail)

    with pytest.raises(SourceError, match="slow"):
        client.get_bytes("https://example.test")


class _FakeClient:
    def __init__(self, payload: Any):
        self.payload = payload

    def get_json(self, url: str) -> Any:
        return self.payload

    def get_text(self, url: str) -> str:
        return str(self.payload)


def test_pypi_source_excludes_prereleases_and_yanked_releases() -> None:
    source = VersionSources(
        _FakeClient(
            {
                "releases": {
                    "1.0.0": [{"yanked": False}],
                    "1.1.0": [{"yanked": True}],
                    "1.2.0rc1": [{"yanked": False}],
                    "9.9.9": [],
                }
            }
        )  # type: ignore[arg-type]
    )

    resolution = source.resolve(_declaration())

    assert resolution.latest == "1.0.0"
    assert resolution.latest_prerelease == "1.2.0rc1"


def test_deferrals_require_reason_status_and_future_review_date(tmp_path: Path) -> None:
    path = tmp_path / "tools" / "version_audit"
    path.mkdir(parents=True)
    (path / "deferrals.json").write_text(
        json.dumps(
            {
                "python:demo": {
                    "status": "deferred",
                    "reason": "Waiting for upstream compatibility",
                    "review_date": "2999-01-01",
                },
                "python:expired": {
                    "status": "deferred",
                    "reason": "Past review date",
                    "review_date": "2000-01-01",
                },
            }
        ),
        encoding="utf-8",
    )

    loaded = audit._load_deferrals(tmp_path)

    assert set(loaded) == {"python:demo"}
    assert loaded["python:demo"]["review_date"] == "2999-01-01"


def test_malformed_deferral_fails_the_audit_closed(tmp_path: Path) -> None:
    path = tmp_path / "tools" / "version_audit"
    path.mkdir(parents=True)
    (path / "deferrals.json").write_text(
        '{"python:demo":{"status":"deferred","reason":""}}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="reason"):
        audit._load_deferrals(tmp_path)


def test_emr_source_accepts_documentation_display_labels() -> None:
    source = VersionSources(
        _FakeClient("<h2>EMR Serverless 7.13.0</h2><a>EMR Serverless 7.12.0</a>")  # type: ignore[arg-type]
    )

    resolution = source.resolve(_declaration(source_kind="emr-serverless", current="emr-7.12.0"))

    assert resolution.latest == "emr-7.13.0"


def test_lambda_source_excludes_unreleased_python_runtime() -> None:
    class LambdaClient:
        def get_text(self, url: str) -> str:
            return "Python 3.14 Python 3.15"

        def get_json(self, url: str) -> Any:
            return [{"cycle": "3.14", "latest": "3.14.6"}]

    source = VersionSources(LambdaClient())  # type: ignore[arg-type]

    resolution = source.resolve(_declaration(source_kind="lambda-runtime", current="3.14"))

    assert resolution.latest == "3.14"


def test_aurora_source_stays_on_declared_engine_line() -> None:
    source = VersionSources(_FakeClient({}))  # type: ignore[arg-type]

    resolution = source.resolve(_declaration(source_kind="aws-cdk-aurora", current="3.12.0"))

    assert resolution.latest is not None
    assert resolution.latest.startswith("3.")


def test_openemr_source_requires_official_release_and_arm64() -> None:
    class OpenEmrClient:
        def get_json(self, url: str) -> object:
            if "hub.docker.com" in url:
                return {
                    "results": [
                        {
                            "name": "8.1.1",
                            "images": [
                                {
                                    "architecture": "arm64",
                                    "digest": f"sha256:{'a' * 64}",
                                }
                            ],
                        },
                        {"name": "8.2.0", "images": [{"architecture": "arm64"}]},
                        {"name": "8.3.0", "images": [{"architecture": "arm64"}]},
                        {"name": "8.2.1", "images": [{"architecture": "amd64"}]},
                    ],
                    "next": None,
                }
            if "api.github.com/repos/openemr/openemr/releases" in url:
                return [
                    {"tag_name": "v8_2_0", "draft": False, "prerelease": False},
                    {"tag_name": "v8_3_0", "draft": True, "prerelease": False},
                ]
            raise AssertionError(f"Unexpected URL: {url}")

        def get_text(self, url: str) -> str:
            raise AssertionError(f"Unexpected URL: {url}")

    resolution = VersionSources(OpenEmrClient()).resolve(  # type: ignore[arg-type]
        _declaration(
            identifier="container:openemr",
            name="openemr/openemr",
            category="container",
            current="8.1.1",
            source_kind="openemr-container",
            metadata={"arm64_digest": f"sha256:{'a' * 64}"},
        )
    )

    assert resolution.latest == "8.2.0"
    assert resolution.latest_prerelease is None
    assert resolution.current_reference_verified is True


@pytest.mark.parametrize(
    ("current", "latest", "expected"),
    [
        ("v6", "v6.2.0", Status.CURRENT),
        ("24", "v24.10.0", Status.CURRENT),
        ("1.25", "1.25.4", Status.CURRENT),
        ("1.0.0", "1.1.0", Status.STABLE_UPDATE),
        ("2.0.0", "1.9.0", Status.MANUAL_REVIEW),
    ],
)
def test_classification_handles_aliases_and_semver(
    current: str,
    latest: str,
    expected: Status,
) -> None:
    declaration = _declaration(current=current, constraint=None, source_kind="github-release")

    status, _ = audit._classify(  # pylint: disable=protected-access
        declaration,
        Resolution(latest=latest, source_url="https://example.test"),
    )

    assert status is expected


def test_python_range_accepting_latest_is_current() -> None:
    declaration = _declaration(current=">=1,<3", constraint="<3,>=1")

    status, note = audit._classify(  # pylint: disable=protected-access
        declaration,
        Resolution(latest="2.4.0", source_url="https://example.test"),
    )

    assert status is Status.CURRENT
    assert "already accepts" in str(note)


def test_aurora_update_always_requires_compatibility_review() -> None:
    declaration = _declaration(source_kind="aws-cdk-aurora", current="3.10.0")

    status, _ = audit._classify(  # pylint: disable=protected-access
        declaration,
        Resolution(latest="3.12.0", source_url="https://example.test"),
    )

    assert status is Status.MANUAL_REVIEW


def test_current_action_tag_requires_immutable_sha_pin() -> None:
    declaration = _declaration(
        category="github-actions",
        source_kind="github-release",
        current="v7",
        metadata={"immutable_sha_pins": False},
    )

    status, note = audit._classify(  # pylint: disable=protected-access
        declaration,
        Resolution(latest="v7.0.1", source_url="https://example.test"),
    )

    assert status is Status.MANUAL_REVIEW
    assert "immutable commit SHA" in str(note)


def test_action_sha_must_match_its_labelled_github_tag() -> None:
    pinned_sha = "a" * 40
    tagged_sha = "b" * 40

    class GitHubClient:
        def get_json(self, url: str) -> object:
            if "/releases" in url:
                return [
                    {
                        "tag_name": "v1.0.0",
                        "draft": False,
                        "prerelease": False,
                    }
                ]
            if "/commits/v1.0.0" in url:
                return {"sha": tagged_sha}
            raise AssertionError(f"Unexpected URL: {url}")

    declaration = _declaration(
        name="actions/example",
        category="github-actions",
        current="v1.0.0",
        source_kind="github-release",
        metadata={
            "repository": "actions/example",
            "immutable_sha_pins": True,
            "revision_labels": {pinned_sha: "v1.0.0"},
        },
    )

    resolution = VersionSources(GitHubClient()).resolve(declaration)  # type: ignore[arg-type]
    status, note = audit._classify(declaration, resolution)

    assert resolution.current_reference_verified is False
    assert status is Status.MANUAL_REVIEW
    assert "does not match" in str(note)


def test_run_audit_isolates_source_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    declarations = (
        _declaration(identifier="python:one", name="one"),
        _declaration(identifier="python:two", name="two"),
    )
    monkeypatch.setattr(audit, "collect_declarations", lambda root: declarations)
    monkeypatch.setattr(audit, "_load_deferrals", lambda root: {})

    class FakeSources:
        def __init__(self, client: object):
            pass

        def resolve(self, declaration: Declaration) -> Resolution:
            if declaration.name == "one":
                raise SourceError("source unavailable")
            return Resolution(latest="1.1.0", source_url="https://example.test")

    monkeypatch.setattr(audit, "VersionSources", FakeSources)

    report = audit.run_audit(tmp_path, generated_at="2026-01-01T00:00:00Z")

    assert report.partial_failure is True
    assert [item.status for item in report.findings] == [
        Status.UNABLE,
        Status.STABLE_UPDATE,
    ]


def test_offline_audit_never_constructs_http_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(audit, "collect_declarations", lambda root: (_declaration(),))
    monkeypatch.setattr(audit, "_load_deferrals", lambda root: {})
    monkeypatch.setattr(
        audit,
        "HttpClient",
        lambda *args, **kwargs: pytest.fail("HTTP client should not be created"),
    )

    report = audit.run_audit(tmp_path, online=False)

    assert report.findings[0].status is Status.UNABLE
    assert report.findings[0].note == "Network lookup disabled"


def test_markdown_escapes_table_values() -> None:
    finding = Finding(
        identifier="demo",
        name="demo|name",
        category="test",
        current="1.0",
        latest="2.0",
        status=Status.STABLE_UPDATE,
        definition="file:1",
        source_kind="test",
        source_url="https://example.test",
    )
    report = AuditReport(
        generated_at="2026-01-01T00:00:00Z",
        repository_root=".",
        findings=(finding,),
        selected_categories=("test",),
    )

    markdown = render_markdown(report)

    assert "demo\\|name" in markdown


def test_cli_writes_reports_and_fail_on_updates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding = Finding(
        identifier="demo",
        name="demo",
        category="test",
        current="1.0",
        latest="2.0",
        status=Status.STABLE_UPDATE,
        definition="file:1",
        source_kind="test",
        source_url="https://example.test",
    )
    report = AuditReport(
        generated_at="2026-01-01T00:00:00Z",
        repository_root=".",
        findings=(finding,),
        selected_categories=("test",),
    )
    monkeypatch.setattr("tools.version_audit.__main__.repository_root", lambda: tmp_path)
    monkeypatch.setattr(
        "tools.version_audit.__main__.collect_declarations",
        lambda root: (_declaration(category="test"),),
    )
    monkeypatch.setattr("tools.version_audit.__main__.run_audit", lambda *args, **kwargs: report)

    exit_code = main(
        [
            "--category",
            "test",
            "--json",
            "report.json",
            "--markdown",
            "report.md",
            "--quiet",
            "--fail-on-updates",
        ]
    )

    assert exit_code == EXIT_UPDATES
    assert json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))["summary"]["updates_found"] is True
    assert (tmp_path / "report.md").read_text(encoding="utf-8").startswith("# Dependency")


def test_cli_offline_success(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("tools.version_audit.__main__.repository_root", lambda: tmp_path)
    monkeypatch.setattr(
        "tools.version_audit.__main__.collect_declarations",
        lambda root: (_declaration(category="test"),),
    )
    monkeypatch.setattr(
        "tools.version_audit.__main__.run_audit",
        lambda *args, **kwargs: AuditReport(
            generated_at="2026-01-01T00:00:00Z",
            repository_root=".",
            findings=(),
            selected_categories=("test",),
        ),
    )

    assert main(["--offline", "--quiet"]) == EXIT_OK


def test_monthly_workflow_invokes_reusable_audit() -> None:
    root = Path(__file__).resolve().parents[2]
    workflow = (root / ".github" / "workflows" / "monthly-version-check.yml").read_text(encoding="utf-8")

    assert "python -m tools.version_audit" in workflow
    assert "pip list --outdated" not in workflow
    assert "issues.create" in workflow
