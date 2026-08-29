"""End-to-end smoke test for a built BLACKBOX standalone binary.

Usage:  python packaging/smoke.py [path-to-blackbox-exe]

Runs the recipient's exact journey on a FRESH BLACKBOX_HOME with the given
binary: version, init (bundled templates), pack, run (provisions a real
runtime from the internet and executes it), verify. Used by CI and the
release workflow on every platform.
"""

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXE = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                      else str(ROOT / "dist" / ("blackbox.exe" if os.name == "nt" else "blackbox")))


def run(*args, cwd=None, expect=0):
    print("+ blackbox", *args)
    p = subprocess.run([EXE, *args], cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    out = (p.stdout or "") + (p.stderr or "")
    print(out.strip()[-2000:])
    if p.returncode != expect:
        raise SystemExit(f"SMOKE FAILED: blackbox {' '.join(args)} -> rc={p.returncode} (expected {expect})")
    return out


def main():
    assert os.path.isfile(EXE), f"binary not found: {EXE}"
    home = tempfile.mkdtemp(prefix="bb-smoke-home-")
    work = tempfile.mkdtemp(prefix="bb-smoke-cwd-")
    env = dict(os.environ, BLACKBOX_HOME=home)
    os.environ.update(env)

    out = run("--version")
    assert "blackbox" in out

    run("doctor")
    run("init", "smoke", cwd=work)
    proj = Path(work) / "smoke"
    assert (proj / "blackbox.yaml").is_file(), "init did not create a project (templates missing?)"
    run("pack", cwd=proj)
    pkg = proj / "smoke.blackbox"
    assert pkg.is_file(), "pack produced no package"

    run("verify", str(pkg), cwd=proj)
    out = run("run", "--yes", str(pkg), cwd=proj)
    assert "Hello from inside a BLACKBOX" in out, "packaged app did not run"
    assert "python:     3.12." in out, "unexpected runtime version in app output"
    assert (proj / "smoke-work" / "output" / "hello.txt").is_file(), "app could not write output/"

    # dependency path: pip/npm resolution inside the frozen binary
    dep = Path(work) / "dep"
    (dep / "src").mkdir(parents=True)
    (dep / "requirements.txt").write_text("six==1.16.0\n")
    (dep / "src" / "main.py").write_text("import six\nprint('SIX', six.__version__)\n")
    manifest = (ROOT / "blackbox" / "cli" / "templates" / "hello" / "blackbox.yaml").read_text()
    (dep / "blackbox.yaml").write_text(manifest.replace("blackbox-template", "dep"))
    run("pack", cwd=dep)
    out = run("run", "--yes", str(dep / "dep.blackbox"), cwd=dep)
    assert "SIX 1.16.0" in out, "dependency layer did not work"

    # layer reuse: running twice must be faster and print no new caching
    out = run("run", "--yes", str(dep / "dep.blackbox"), cwd=dep)
    assert "caching" not in out, "layers were not reused from cache"

    print(json.dumps({"smoke": "PASS", "platform": sys.platform, "exe": EXE}))


if __name__ == "__main__":
    main()
