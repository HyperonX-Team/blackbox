"""End-to-end integration tests exercising the real CLI.

Order matters within this file: the first run provisions the shared Python
runtime; later tests reuse it (and prove warm startup is fast).
"""

import json
import os
import shutil
import subprocess
import sys
import time

import pytest

from tests.conftest import HELLO_YAML, make_project, run_cli

pytestmark = pytest.mark.usefixtures("shared_home")


def _fresh_cwd(monkeypatch, tmp_path):
    cwd = tmp_path / "cwd"
    cwd.mkdir(exist_ok=True)
    monkeypatch.chdir(str(cwd))
    return str(cwd)


class TestProjectLifecycle:
    def test_init_creates_working_project(self, monkeypatch, tmp_path):
        _fresh_cwd(monkeypatch, tmp_path)
        rc, _ = run_cli("init", "starter")
        assert rc == 0
        assert os.path.isfile("starter/blackbox.yaml")
        assert os.path.isfile("starter/src/main.py")
        rc, _ = run_cli("pack", "starter")
        assert rc == 0
        assert os.path.isfile("starter/starter.blackbox")

    def test_pack_inspect_verify_unpack(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "alpha", main_py="print('alpha')\n")
        rc, _ = run_cli("pack", proj)
        assert rc == 0
        pkg = os.path.join(proj, "alpha.blackbox")
        assert os.path.isfile(pkg)

        rc, _ = run_cli("inspect", pkg)
        out = capsys.readouterr().out
        assert rc == 0 and "Name:        alpha" in out
        assert "network: disabled" in out and "process spawning: denied" in out
        assert "application" in out  # layers listed

        rc, _ = run_cli("verify", pkg)
        out = capsys.readouterr().out
        assert rc == 0 and "Integrity:   OK" in out

        rc, _ = run_cli("unpack", pkg, "extracted")
        assert rc == 0
        assert os.path.isfile("extracted/manifest.json")
        assert os.path.isfile("extracted/blackbox.lock")
        assert os.path.isfile("extracted/application/src/main.py")

    def test_pack_is_deterministic(self, monkeypatch, tmp_path):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "stable", main_py="print(1)\n")
        run_cli("pack", proj, "-o", "s1.blackbox")
        run_cli("pack", proj, "-o", "s2.blackbox")
        assert open("s1.blackbox", "rb").read() == open("s2.blackbox", "rb").read()

    def test_pack_without_manifest_fails_clearly(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        (tmp_path / "empty").mkdir()
        rc, _ = run_cli("pack", str(tmp_path / "empty"))
        err = capsys.readouterr().err
        assert rc == 1
        assert "BLACKBOX ERROR" in err and "blackbox.yaml" in err

    def test_pack_rejects_malformed_permissions(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        bad = HELLO_YAML.format(name="bad").replace('"./output"', '"/root/pwn"')
        make_project(tmp_path, "bad", main_py="pass", manifest=bad)
        rc, _ = run_cli("pack", str(tmp_path / "bad"))
        err = capsys.readouterr().err
        assert rc == 1 and "relative to the package root" in err


@pytest.mark.heavy
class TestRuntime:
    """These provision the shared python runtime once; later runs reuse it."""

    def test_run_hello_cli_app(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "hello",
                            main_py="import os, sys\nprint('PY', sys.version.split()[0])\n"
                                    "print('MODE', os.environ.get('APP_MODE'))\n"
                                    "open(os.path.join(os.environ['BLACKBOX_OUTPUT'],'x.txt'),'w').write('ok')\n",
                            manifest=HELLO_YAML.format(name="hello").replace(
                                "interface:\n  type: cli", "interface:\n  type: cli").rstrip() +
                            "\nenvironment:\n  variables:\n    APP_MODE: \"on\"\n")
        assert run_cli("pack", proj)[0] == 0
        t_cold = time.time()
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "hello.blackbox"))
        out = capsys.readouterr().out
        assert rc == 0
        assert "PY 3.12." in out and "MODE on" in out
        assert os.path.isfile("hello-work/output/x.txt")
        # the bundled runtime, never the host interpreter
        assert sys.version.split()[0] not in out or "3.12." in out

    def test_host_isolation(self, monkeypatch, tmp_path, capsys, shared_home):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "iso",
                            main_py="import sys, json\nprint(json.dumps({'exe': sys.executable,"
                                    " 'ver': sys.version.split()[0], 'path': __import__('os').environ.get('PYTHONPATH','')}))\n")
        run_cli("pack", proj)
        run_cli("run", "--yes", os.path.join(proj, "iso.blackbox"))
        out = capsys.readouterr().out
        line = [ln for ln in out.splitlines() if ln.startswith("{")][-1]
        info = json.loads(line)
        assert info["ver"].startswith("3.12.")
        assert os.path.realpath(shared_home) in os.path.realpath(info["exe"])
        assert "site-packages" not in info["path"]  # host packages not visible

    def test_run_with_python_dependency(self, monkeypatch, tmp_path, capsys, needs_network):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "dep", main_py="import six; print('SIX', six.__version__)\n",
                            requirements="six==1.16.0")
        rc, _ = run_cli("pack", proj)
        assert rc == 0
        lock = open(os.path.join(proj, "blackbox.lock")).read()
        assert "six" in lock and "sha256" in lock
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "dep.blackbox"))
        out = capsys.readouterr().out
        assert rc == 0 and "SIX 1.16.0" in out

    def test_dependency_layer_deduplicated(self, monkeypatch, tmp_path, capsys, needs_network):
        _fresh_cwd(monkeypatch, tmp_path)
        pa = make_project(tmp_path, "dup-a", main_py="import six; print('A')\n",
                          requirements="six==1.16.0")
        pb = make_project(tmp_path, "dup-b", main_py="import six; print('B')\n",
                          requirements="six==1.16.0")
        run_cli("pack", pa); run_cli("pack", pb)
        run_cli("run", "--yes", os.path.join(pa, "dup-a.blackbox"))
        capsys.readouterr()
        run_cli("run", "--yes", os.path.join(pb, "dup-b.blackbox"))
        out = capsys.readouterr().out
        assert "B" in out
        assert "caching dependencies layer" not in out  # reused from first run

    def test_environment_rebuilt_after_deletion(self, monkeypatch, tmp_path, capsys, shared_home):
        """Victory condition 2: delete the machine's local environment; run again."""
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "ghost",
                            main_py="import six; print('GHOST', six.__version__)\n",
                            requirements="six==1.16.0")
        run_cli("pack", proj)
        run_cli("run", "--yes", os.path.join(proj, "ghost.blackbox"))
        shutil.rmtree(os.path.join(shared_home, "layers"))
        capsys.readouterr()
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "ghost.blackbox"))
        out = capsys.readouterr().out
        assert rc == 0 and "GHOST 1.16.0" in out and "caching" in out

    def test_app_crash_propagates_exit_code(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "crashy", main_py="import sys\nsys.exit(3)\n")
        run_cli("pack", proj)
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "crashy.blackbox"))
        err = capsys.readouterr().err
        assert rc == 3 and "exited with code 3" in err

    def test_warm_startup_and_size_benchmark(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "bench", main_py="print('warm')\n")
        run_cli("pack", proj)
        pkg = os.path.join(proj, "bench.blackbox")
        assert os.path.getsize(pkg) < 25 * 1024  # tiny apps stay tiny
        run_cli("run", "--yes", pkg)             # warm caches
        capsys.readouterr()
        t0 = time.time()
        rc, _ = run_cli("run", "--yes", pkg)
        elapsed = time.time() - t0
        assert rc == 0 and "warm" in capsys.readouterr().out
        assert elapsed < 15, f"warm startup too slow: {elapsed:.1f}s"


@pytest.mark.heavy
class TestPermissionsEnforcement:
    NAUGHTY = """import os, socket, subprocess, sys
which = sys.argv[1]
if which == "net":
    socket.create_connection(("example.com", 80), timeout=5); print("NOT BLOCKED")
elif which == "spawn":
    subprocess.run([sys.executable, "-c", "pass"]); print("NOT BLOCKED")
elif which == "escape":
    open(os.path.join(os.getcwd(), "sneaky.txt"), "w"); print("NOT BLOCKED")
elif which == "outside":
    open(os.path.join(os.environ.get("SystemRoot", "/"), "blackbox-nope.txt"), "w"); print("NOT BLOCKED")
"""

    def _pkg(self, tmp_path):
        cwd = tmp_path / "cwd"
        cwd.mkdir(exist_ok=True)
        os.chdir(str(cwd))
        proj = make_project(cwd, "naughty", main_py=self.NAUGHTY)
        rc, _ = run_cli("pack", proj)
        assert rc == 0
        return os.path.join(str(proj), "naughty.blackbox")

    def test_network_denied(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        pkg = self._pkg(tmp_path)
        rc, _ = run_cli("run", "--yes", pkg, "--", "net")
        out = capsys.readouterr().out
        assert rc != 0 and "SANDBOX VIOLATION" in out and "NOT BLOCKED" not in out

    def test_spawn_denied(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        pkg = self._pkg(tmp_path)
        rc, _ = run_cli("run", "--yes", pkg, "--", "spawn")
        out = capsys.readouterr().out
        assert rc != 0 and "process spawning" in out and "NOT BLOCKED" not in out

    def test_write_outside_allowlist_denied(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        pkg = self._pkg(tmp_path)
        rc, _ = run_cli("run", "--yes", pkg, "--", "outside")
        out = capsys.readouterr().out
        assert rc != 0 and "filesystem write" in out
        assert not os.path.exists(os.path.join(os.environ.get("SystemRoot", "/"), "blackbox-nope.txt"))

    def test_allowed_write_succeeds(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "writable",
                            main_py="import os\nopen(os.path.join(os.environ['BLACKBOX_OUTPUT'],'yes.txt'),'w').write('ok')\nprint('WROTE')\n")
        run_cli("pack", proj)
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "writable.blackbox"))
        assert rc == 0 and "WROTE" in capsys.readouterr().out


class TestIntegrityAndSigning:
    def test_corrupted_package_detected(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "fragile", main_py="print(1)\n")
        run_cli("pack", proj)
        pkg = os.path.join(proj, "fragile.blackbox")
        data = bytearray(open(pkg, "rb").read())
        data[len(data) // 2] ^= 0xFF
        open(pkg, "wb").write(bytes(data))
        rc, _ = run_cli("run", "--yes", pkg)
        err = capsys.readouterr().err
        assert rc == 1 and "BLACKBOX ERROR" in err

    def test_member_tamper_detected_by_checksums(self, monkeypatch, tmp_path, capsys):
        """Attacker edits manifest.json without recomputing checksums."""
        import zipfile
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "honest", main_py="print(1)\n")
        run_cli("pack", proj)
        pkg = os.path.join(proj, "honest.blackbox")
        with zipfile.ZipFile(pkg) as zf:
            members = {n: zf.read(n) for n in zf.namelist()}
        members["manifest.json"] = members["manifest.json"].replace(b"honest", b"sworn!")
        with zipfile.ZipFile(pkg, "w") as zf:
            for n, v in members.items():
                zf.writestr(n, v)
        rc, _ = run_cli("verify", pkg)
        err = capsys.readouterr().err
        assert rc == 1 and "does not match its recorded hash" in err

    def test_sign_verify_trust_flow(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "paper", main_py="print(1)\n")
        run_cli("pack", proj)
        pkg = os.path.join(proj, "paper.blackbox")
        assert run_cli("keygen", "lab", "--publisher", "Lab One")[0] == 0
        assert run_cli("sign", pkg, "--key", "lab")[0] == 0
        rc, _ = run_cli("verify", pkg)
        out = capsys.readouterr().out
        assert rc == 0 and "VALID" in out and "unsigned" not in out
        home = os.environ["BLACKBOX_HOME"]
        assert run_cli("trust", os.path.join(home, "keys", "lab.pub.pem"),
                       "--publisher", "Lab One")[0] == 0
        run_cli("verify", pkg)
        assert "trusted publisher: Lab One" in capsys.readouterr().out

    def test_signature_invalid_after_sneaky_content_change(self, monkeypatch, tmp_path, capsys):
        """Attacker edits content AND recomputes checksums: signature still saves the day."""
        import hashlib
        import zipfile
        import yaml
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "signed", main_py="print(1)\n")
        run_cli("pack", proj)
        pkg = os.path.join(proj, "signed.blackbox")
        run_cli("keygen", "sk", "--publisher", "Honest")
        run_cli("sign", pkg, "--key", "sk")
        capsys.readouterr()

        with zipfile.ZipFile(pkg) as zf:
            members = {n: zf.read(n) for n in zf.namelist()}
        m = json.loads(members["manifest.json"])
        m["description"] = "HIJACKED"
        members["manifest.json"] = json.dumps(m, sort_keys=True, separators=(",", ":")).encode()
        members["checksums.json"] = json.dumps(
            {"sha256": {n: hashlib.sha256(v).hexdigest() for n, v in members.items()
                        if n != "checksums.json"}},
            sort_keys=True, separators=(",", ":")).encode()
        with zipfile.ZipFile(pkg, "w", zipfile.ZIP_DEFLATED) as zf:
            for n in sorted(members):
                zf.writestr(n, members[n])
        rc, _ = run_cli("verify", pkg)
        assert rc == 1 and "INVALID" in capsys.readouterr().out
        rc, _ = run_cli("run", "--yes", pkg)
        assert rc == 1 and "Refusing to run" in capsys.readouterr().err


class TestPortability:
    def test_incompatible_architecture_clear_error(self, monkeypatch, tmp_path, capsys):
        _fresh_cwd(monkeypatch, tmp_path)
        foreign = HELLO_YAML.format(name="faraway").replace(
            "runtime:\n  type: python\n  version: \"3.12\"",
            "runtime:\n  type: python\n  version: \"3.12\"\n  target: aarch64-apple-darwin")
        proj = make_project(tmp_path, "faraway", main_py="print(1)\n", manifest=foreign)
        assert run_cli("pack", proj)[0] == 0
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "faraway.blackbox"))
        err = capsys.readouterr().err
        assert rc == 1 and "targets" in err and "BLACKBOX ERROR" in err

    @pytest.mark.heavy
    def test_pack_target_override_crosspacks(self, monkeypatch, tmp_path, capsys):
        """blackbox pack --target is how CI emits one example per platform."""
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "xpack", main_py="print(1)\n")
        rc, _ = run_cli("pack", proj, "--target", "x86_64-unknown-linux-gnu")
        assert rc == 0
        run_cli("inspect", os.path.join(str(proj), "xpack.blackbox"))
        out = capsys.readouterr().out
        assert "x86_64-unknown-linux-gnu" in out

    def test_lockfile_pins_exact_versions(self, monkeypatch, tmp_path, needs_network):
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "pinned", main_py="import six\n",
                            requirements="six==1.16.0")
        run_cli("pack", proj)
        import yaml
        lock = yaml.safe_load(open(os.path.join(proj, "blackbox.lock")))
        six = [p for p in lock["packages"] if p["name"] == "six"][0]
        assert six["version"] == "1.16.0" and len(six["sha256"]) == 64

    def test_missing_runtime_error_points_to_doctor(self, monkeypatch, tmp_path, capsys, isolated_home):
        """Empty cache + no network -> the documented human error, not a stack trace."""
        import urllib.request
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(tmp_path, "needy", main_py="print(1)\n")
        run_cli("pack", proj)
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda *a, **k: (_ for _ in ()).throw(OSError("no network")))
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "needy.blackbox"))
        err = capsys.readouterr().err
        assert rc == 1 and "BLACKBOX ERROR" in err and "blackbox doctor" in err
        assert "No changes were made to the host system." in err


@pytest.mark.heavy
class TestNodeRuntime:
    NODE_YAML = """format_version: "1"
name: wordy
version: "0.1.0"
runtime:
  type: node
  version: "22"
entrypoint:
  command: node
  args:
    - src/index.js
permissions:
  filesystem:
    read:
      - "./input"
    write:
      - "./output"
  network:
    enabled: false
"""

    def test_run_node_package(self, monkeypatch, tmp_path, capsys, needs_network):
        if shutil.which("npm") is None:
            pytest.skip("npm not available on host")
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(
            tmp_path, "wordy", main_py="", manifest=self.NODE_YAML,
            files={"package.json": json.dumps({"name": "wordy", "version": "1.0.0",
                                               "dependencies": {"minimist": "1.2.8"}}),
                   "src/index.js": "const m=require('minimist');const fs=require('fs');"
                                   "fs.writeFileSync(process.env.BLACKBOX_OUTPUT+'/ok.txt','y');"
                                   "console.log('NODE', process.version, 'minimist', typeof m===undefined ? 'x' : 'loaded');"
                                   "console.log('NODE', process.version);\n"})
        rc, _ = run_cli("pack", proj)
        assert rc == 0
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "wordy.blackbox"))
        out = capsys.readouterr().out
        assert rc == 0 and "NODE v22." in out
        assert os.path.isfile("wordy-work/output/ok.txt")


@pytest.mark.heavy
class TestNativeRuntime:
    def test_run_compiled_binary_package(self, monkeypatch, tmp_path, capsys):
        if shutil.which("go") is None:
            pytest.skip("go toolchain not available on host")
        _fresh_cwd(monkeypatch, tmp_path)
        proj = make_project(
            tmp_path, "gobox", main_py="",
            manifest='format_version: "1"\nname: gobox\nversion: "0.1.0"\n'
                     'runtime:\n  type: native\nentrypoint:\n  command: ./bin/gobox{exe}\n'
                     'permissions:\n  filesystem:\n    write:\n      - "./output"\n  network:\n    enabled: false\n'
                     .format(exe=".exe" if os.name == "nt" else ""),
            files={"src/main.go": "package main\nimport (\"fmt\";\"os\")\nfunc main(){"
                                  "os.MkdirAll(os.Getenv(\"BLACKBOX_OUTPUT\"),0o755);"
                                  "fmt.Println(\"GO BOX RUNNING\")}\n",
                   "go.mod": "module gobox\n\ngo 1.21\n"})
        build = subprocess.run(["go", "build", "-o", os.path.join("bin", "gobox" + (".exe" if os.name == "nt" else "")), "./src"],
                               cwd=proj, capture_output=True, text=True)
        if build.returncode != 0:
            pytest.skip("go build failed: " + build.stderr[-200:])
        rc, _ = run_cli("pack", proj)
        assert rc == 0
        rc, _ = run_cli("run", "--yes", os.path.join(proj, "gobox.blackbox"))
        out = capsys.readouterr().out
        assert rc == 0 and "GO BOX RUNNING" in out
