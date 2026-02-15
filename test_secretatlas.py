"""Comprehensive tests for SecretAtlas — unit, integration, and property-based."""
import json, tempfile
from pathlib import Path
import pytest
from hypothesis import given, strategies as st, settings
from secretatlas import SecretAtlas, Finding, scan_env, scan_hardcoded, scan_k8s, scan_terraform, scan_gha

@pytest.fixture
def workspace(tmp_path):
    (tmp_path / ".env").write_text("DB_PASSWORD=supersecret123\nAPI_KEY=abc123\n# comment line\n")
    (tmp_path / "app.py").write_text('password = "MyP@ssw0rd_secure"\napi_key = "sk-abc123def456ghi789jkl012mno"\n')
    (tmp_path / "k8s.yaml").write_text("apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-creds\ndata:\n  pw: base64\n")
    (tmp_path / "main.tf").write_text('variable "db" {\n  sensitive = true\n}\nresource "aws_secretsmanager_secret" "myapi" {}\n')
    gha = tmp_path / ".github" / "workflows"
    gha.mkdir(parents=True)
    (gha / "ci.yml").write_text("jobs:\n  deploy:\n    env:\n      TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n      KEY: ${{ secrets.API_KEY }}\n")
    return tmp_path

def test_scan_env_finds_variables(workspace):
    findings = scan_env(str(workspace))
    names = {f.name for f in findings}
    assert "DB_PASSWORD" in names
    assert "API_KEY" in names
    assert all(f.source == "env_file" for f in findings)

def test_scan_env_skips_comments(workspace):
    findings = scan_env(str(workspace))
    assert not any(f.name.startswith("#") for f in findings)

def test_scan_hardcoded_detects_password(workspace):
    findings = scan_hardcoded(str(workspace))
    assert any(f.stype == "password" and f.severity == "critical" for f in findings)
    assert all(f.hardcoded is True for f in findings)

def test_scan_hardcoded_detects_openai_key(workspace):
    findings = scan_hardcoded(str(workspace))
    assert any(f.stype == "openai_key" and f.severity == "critical" for f in findings)

def test_scan_k8s_finds_secret_resource(workspace):
    findings = scan_k8s(str(workspace))
    assert any(f.name == "db-creds" and f.source == "kubernetes" for f in findings)
    assert any(f.severity == "high" for f in findings)

def test_scan_terraform_sensitive_and_resource(workspace):
    findings = scan_terraform(str(workspace))
    assert any(f.stype == "tf_sensitive" for f in findings)
    assert any(f.name == "myapi" and f.stype == "tf_secret" for f in findings)

def test_scan_gha_extracts_secret_names(workspace):
    findings = scan_gha(str(workspace))
    names = {f.name for f in findings}
    assert "DEPLOY_TOKEN" in names
    assert "API_KEY" in names
    assert all(f.source == "github_actions" for f in findings)

def test_full_scan_json_roundtrip(workspace):
    atlas = SecretAtlas(str(workspace)).scan()
    data = json.loads(atlas.to_json())
    assert data["summary"]["total"] >= 6
    assert len(data["findings"]) == data["summary"]["total"]
    assert all("name" in f and "source" in f for f in data["findings"])

def test_full_scan_table_format(workspace):
    table = SecretAtlas(str(workspace)).scan().to_table()
    assert "NAME" in table and "SOURCE" in table
    assert "Total:" in table and "Critical:" in table

def test_summary_counts_consistent(workspace):
    s = SecretAtlas(str(workspace)).scan().summary()
    assert s["total"] == sum(s["by_source"].values())
    assert s["total"] > 0
    assert s["hardcoded"] >= 1

def test_empty_directory_returns_zero(tmp_path):
    atlas = SecretAtlas(str(tmp_path)).scan()
    s = atlas.summary()
    assert s["total"] == 0 and s["hardcoded"] == 0

def test_selective_scan_filters_sources(workspace):
    atlas = SecretAtlas(str(workspace)).scan(["env"])
    assert len(atlas.findings) >= 2
    assert all(f.source == "env_file" for f in atlas.findings)

def test_finding_default_values():
    f = Finding("test_key", "env_file", "/tmp/test")
    assert f.severity == "medium"
    assert f.hardcoded is False
    assert f.stype == "generic"
    assert len(f.ts) > 10

@given(content=st.text(min_size=0, max_size=300))
@settings(max_examples=50)
def test_hardcoded_scanner_never_crashes_on_fuzz(content):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "fuzz.py").write_text(content, errors='replace')
        findings = scan_hardcoded(d)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

@given(content=st.text(min_size=0, max_size=300))
@settings(max_examples=50)
def test_env_scanner_never_crashes_on_fuzz(content):
    with tempfile.TemporaryDirectory() as d:
        Path(d, ".env").write_text(content, errors='replace')
        findings = scan_env(d)
        assert isinstance(findings, list)
        assert all(isinstance(f, Finding) for f in findings)

@given(content=st.text(min_size=0, max_size=300))
@settings(max_examples=50)
def test_k8s_scanner_never_crashes_on_fuzz(content):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "test.yaml").write_text(content, errors='replace')
        findings = scan_k8s(d)
        assert isinstance(findings, list)
