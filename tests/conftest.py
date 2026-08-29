import os
import shutil
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blackbox.cli.main import main as bb_main  # noqa: E402


@pytest.fixture(scope="session")
def shared_home(tmp_path_factory):
    """One BLACKBOX home for integration tests: runtimes are downloaded once."""
    home = tmp_path_factory.mktemp("blackbox-home")
    os.environ["BLACKBOX_HOME"] = str(home)
    yield str(home)
    os.environ.pop("BLACKBOX_HOME", None)


@pytest.fixture()
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    return str(tmp_path / "bbhome")


def run_cli(*argv):
    from blackbox.errors import render_error
    try:
        rc = bb_main(list(argv))
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 0
    except Exception as e:  # noqa: BLE001 - tests assert on rendered errors instead
        return 99, render_error(e)
    return rc, ""


HELLO_YAML = """format_version: "1"
name: {name}
version: "0.1.0"
description: test project
publisher: Tests
runtime:
  type: python
  version: "3.12"
entrypoint:
  command: python
  args:
    - src/main.py
permissions:
  filesystem:
    read:
      - "./input"
    write:
      - "./output"
  network:
    enabled: false
"""


def make_project(root, name, *, main_py, requirements=None, manifest=None, files=None):
    root = str(root)
    os.makedirs(os.path.join(root, name, "src"), exist_ok=True)
    proj = os.path.join(root, name)
    with open(os.path.join(proj, "blackbox.yaml"), "w", encoding="utf-8", newline="\n") as f:
        f.write(manifest or HELLO_YAML.format(name=name))
    with open(os.path.join(proj, "src", "main.py"), "w", encoding="utf-8", newline="\n") as f:
        f.write(main_py)
    with open(os.path.join(proj, "requirements.txt"), "w", encoding="utf-8") as f:
        f.write((requirements or "") + "\n")
    for rel, content in (files or {}).items():
        full = os.path.join(proj, *rel.split("/"))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    return proj


@pytest.fixture(scope="session")
def needs_network():
    import urllib.request
    try:
        urllib.request.urlopen("https://pypi.org/simple/", timeout=8)
    except OSError:
        pytest.skip("no network: skipping tests that provision runtimes/dependencies")
