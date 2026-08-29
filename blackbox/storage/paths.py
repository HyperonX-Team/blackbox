"""BLACKBOX home directory layout.

~/.blackbox/
    objects/sha256/...   content-addressed store (immutable)
    runtimes/python/...  standalone runtimes
    packages/...         installed (unpacked) packages
    logs/
"""

import json
import os
import pathlib


def home() -> pathlib.Path:
    override = os.environ.get("BLACKBOX_HOME")
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".blackbox"


def ensure_home() -> dict:
    h = home()
    dirs = {
        "root": h,
        "objects": h / "objects",
        "runtimes": h / "runtimes",
        "packages": h / "packages",
        "tmp": h / "tmp",
        "logs": h / "logs",
        "keys": h / "keys",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def index_path() -> pathlib.Path:
    return home() / "packages" / "index.json"


def load_index() -> dict:
    p = index_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_index(idx: dict):
    p = index_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(idx, sort_keys=True, indent=2), encoding="utf-8")
    os.replace(tmp, p)
