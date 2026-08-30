"""Fast tests for the new BLACKBOX feature set (no runtime provisioning)."""

import json

import pytest

from blackbox.manifest import load_manifest
from blackbox.sandbox.policy import build_policy
from blackbox.sandbox.shim.netmatch import host_allowed
from blackbox.packaging import builder, format as fmt, reader
from blackbox.crypto import sealing, signing
from blackbox.cli import commands

MIN_YAML = """format_version: "1"
name: feat
version: "0.1.0"
description: t
publisher: t
runtime:
  type: python
  version: "3.12"
entrypoint:
  command: python
  args: [src/main.py]
permissions:
  filesystem:
    read: ["./input"]
    write: ["./output"]
  network:
    enabled: true
    allow: ["api.example.com", "*.discord.com"]
interface:
  type: cli
"""


def _project(p):
    p.mkdir(parents=True, exist_ok=True)
    (p / "src").mkdir()
    (p / "src" / "main.py").write_text("print('ok')\n")
    (p / "requirements.txt").write_text("")
    (p / "blackbox.yaml").write_text(MIN_YAML)
    return p


def _args(**kw):
    return type("A", (), kw)


def test_manifest_allow_limits_gui_entrypoints():
    y = MIN_YAML.replace("type: cli", "type: gui") + (
        "\nlimits:\n  memory_mb: 512\n  cpu_percent: 50\n"
        "entrypoints:\n  worker:\n    command: python\n    args: [src/main.py]\n")
    m = load_manifest(y)
    assert m["permissions"]["network"]["allow"] == ["api.example.com", "*.discord.com"]
    assert m["limits"] == {"memory_mb": 512, "cpu_percent": 50}
    assert m["interface"]["type"] == "gui"
    assert m["entrypoints"]["worker"]["args"] == ["src/main.py"]


def test_manifest_defaults_backwards_compatible():
    m = load_manifest(MIN_YAML)
    assert m["limits"] == {}
    assert m["entrypoints"] == {}
    assert m["permissions"]["network"]["enabled"] is True


def test_manifest_rejects_bad_allow_limits_entrypoints():
    with pytest.raises(Exception):
        load_manifest(MIN_YAML.replace("api.example.com", "not a host"))
    with pytest.raises(Exception):
        load_manifest(MIN_YAML + "\nlimits:\n  memory_mb: -5\n")
    with pytest.raises(Exception):
        load_manifest(MIN_YAML + "\nlimits:\n  wat: 1\n")
    with pytest.raises(Exception):
        load_manifest(MIN_YAML + "\nentrypoints:\n  worker:\n    command: node\n")


def test_netmatch():
    allow = ["api.example.com", "*.discord.com"]
    assert host_allowed("api.example.com", allow)
    assert host_allowed("gateway.discord.com", allow)
    assert host_allowed("discord.com", allow)
    assert not host_allowed("evil.com", allow)
    assert host_allowed("anything.com", [])
    assert host_allowed("anything.com", ["*"])
    assert host_allowed("API.Example.COM.", allow)


def test_policy_data_dir_and_allow(tmp_path):
    m = load_manifest(MIN_YAML)
    work = tmp_path / "work"
    work.mkdir()
    data = tmp_path / "data"
    pol = build_policy(m, app_dir=str(tmp_path / "app"), site_dir=None,
                       runtime_root=str(tmp_path / "rt"), work_dir=str(work),
                       trusted_read=[], data_dir=str(data))
    assert data.exists()
    assert str(data) in pol["read_allowed"]
    assert str(data) in pol["write_allowed"]
    assert sorted(pol["network_allow"]) == ["*.discord.com", "api.example.com"]
    assert pol["gui"] is False
    assert pol["limits"] == {}


def test_pack_provenance_and_inspect(tmp_path, capsys):
    proj = _project(tmp_path / "proj")
    out = builder.pack(proj, tmp_path / "feat.blackbox")
    pkg = reader.open_package(out)
    assert fmt.PROVENANCE in pkg.members
    assert fmt.SECRETS not in pkg.members
    prov = json.loads(pkg.members[fmt.PROVENANCE])
    assert prov["target"] and prov["tool"].startswith("blackbox")
    rc = commands.cmd_inspect(_args(package=str(out)))
    assert rc == 0
    assert "Provenance:" in capsys.readouterr().out


def test_seal_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "h1"))
    signing.keygen("lab", "Lab")
    pub = (tmp_path / "h1" / "keys" / "lab.seal.pub.pem").read_bytes()
    blob = sealing.seal_bytes(b"TOKEN=abc\nOTHER=def\n", pub)
    assert json.loads(blob)["alg"] == "x25519-aesgcm-256"
    assert sealing.open_sealed(blob) == {"TOKEN": "abc", "OTHER": "def"}


def test_seal_requires_matching_key(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "h2"))
    signing.keygen("a", "A")
    pub = (tmp_path / "h2" / "keys" / "a.seal.pub.pem").read_bytes()
    blob = sealing.seal_bytes(b"K=V\n", pub)
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "h3"))
    with pytest.raises(Exception, match="seal key"):
        sealing.open_sealed(blob)


def test_seal_cmd_attaches_member(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "h4"))
    signing.keygen("lab", "Lab")
    proj = _project(tmp_path / "proj")
    pkgp = builder.pack(proj, tmp_path / "s.blackbox")
    sec = tmp_path / "sec.env"
    sec.write_text("TOKEN=xyz\n")
    rc = commands.cmd_seal(_args(package=str(pkgp), secrets=str(sec), to=None, key="lab"))
    assert rc == 0
    pkg = reader.open_package(pkgp)
    assert fmt.SECRETS in pkg.members
    assert sealing.open_sealed(pkg.members[fmt.SECRETS]) == {"TOKEN": "xyz"}


def test_explain_diff_audit(tmp_path, capsys):
    a = builder.pack(_project(tmp_path / "p1"), tmp_path / "a.blackbox")
    proj2 = _project(tmp_path / "p2")
    (proj2 / "src" / "main.py").write_text("print('changed')\n")
    b = builder.pack(proj2, tmp_path / "b.blackbox")

    commands.cmd_explain(_args(package=str(a)))
    o1 = capsys.readouterr().out
    assert "dry-run" in o1 and "api.example.com" in o1

    commands.cmd_diff(_args(package_a=str(a), package_b=str(b)))
    o2 = capsys.readouterr().out
    assert "changed" in o2 and "main.py" in o2

    commands.cmd_audit(_args(package=str(a)))
    o3 = capsys.readouterr().out
    assert "AUDIT" in o3


def test_export_docker(tmp_path):
    a = builder.pack(_project(tmp_path / "proj"), tmp_path / "a.blackbox")
    outd = tmp_path / "docker"
    commands.cmd_export_docker(_args(package=str(a), out=str(outd)))
    df = (outd / "Dockerfile").read_text()
    assert "FROM python:3.12-slim" in df and "USER nobody" in df
    assert (outd / "application" / "src" / "main.py").is_file()


def test_gc_dry_run(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "h5"))
    commands.cmd_gc(_args(apply=False, older_than=None))
    assert "dry-run" in capsys.readouterr().out


def test_limits_helpers():
    import sys
    from blackbox.sandbox import limits
    d = limits.describe({"memory_mb": 256}, "x86_64-pc-windows-msvc")
    assert "mem<=256MB" in d and "enforced" in d
    assert limits.describe({}, "x86_64-pc-windows-msvc") == ""
    pre = limits.make_preexec({"memory_mb": 10})
    if sys.platform == "win32":
        assert pre is None
    else:
        assert callable(pre)

def test_upgrade_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "h6"))
    signing.keygen("lab", "Lab")
    a = builder.pack(_project(tmp_path / "p1"), tmp_path / "a.blackbox")
    proj2 = _project(tmp_path / "p2")
    (proj2 / "src" / "main.py").write_text("print('v2')\n")
    b = builder.pack(proj2, tmp_path / "b.blackbox")
    signing.attach_signature(b, signing.sign_package(reader.open_package(b), key_name="lab"))

    c = builder.pack(_project(tmp_path / "p3"), tmp_path / "c.blackbox")  # unsigned candidate
    with pytest.raises(Exception, match="unsigned"):
        commands.cmd_upgrade(_args(package=str(a), from_url=str(c), yes=False))

    signing.trust_key(tmp_path / "h6" / "keys" / "lab.pub.pem", "Lab")
    rc = commands.cmd_upgrade(_args(package=str(a), from_url=str(b), yes=False))
    assert rc == 0
    assert reader.open_package(a).package_id() == reader.open_package(b).package_id()
    assert (tmp_path / "a.blackbox.bak").is_file()
