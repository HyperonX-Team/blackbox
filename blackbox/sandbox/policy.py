"""Sandbox policy: materializes manifest permissions into an enforceable policy.

Two enforcement tiers (documented in docs/security.md):

  1. Platform jail (strongest available):
       linux   -> bubblewrap (bwrap) filesystem bind + network namespace
       macOS   -> sandbox-exec profile
       windows -> not implemented in MVP
  2. Runtime shim (always on, in-process):
       sitecustomize.py / node_guard.js enforcing network denial (with an
       optional per-host allowlist), spawn denial and the filesystem write
       allowlist from inside the interpreter.

The shim is defense-in-depth and a contract-enforcer, not a kernel boundary.
"""

import json
import os

from blackbox.errors import BlackboxError

MODE = os.environ.get("BLACKBOX_SANDBOX_ENFORCE", "1")


def build_policy(manifest: dict, *, app_dir: str, site_dir: str, runtime_root: str,
                 work_dir: str, trusted_read: list, data_dir: str = None) -> dict:
    perms = manifest["permissions"]
    work_dir = os.path.abspath(str(work_dir))
    resolved_read = [os.path.realpath(os.path.join(work_dir, p[2:])) for p in perms["filesystem"]["read"]]
    resolved_write = [os.path.realpath(os.path.join(work_dir, p[2:])) for p in perms["filesystem"]["write"]]
    for p in perms["filesystem"]["write"]:
        os.makedirs(os.path.join(work_dir, *p[2:].split("/")), exist_ok=True)

    data_dir = os.path.realpath(str(data_dir)) if data_dir else None
    if data_dir:
        os.makedirs(data_dir, exist_ok=True)
        resolved_read.append(data_dir)
        resolved_write.append(data_dir)

    readable = sorted(set(
        [os.path.realpath(app_dir), os.path.realpath(site_dir or ""), runtime_root]
        + resolved_read + [os.path.realpath(t) for t in trusted_read]
    ))
    writable = sorted(set(resolved_write + [os.path.realpath(os.path.join(work_dir, "_blackbox_tmp"))]))
    return {
        "network": bool(perms["network"]["enabled"]),
        "network_allow": sorted(set(perms["network"].get("allow", []))),
        "spawn": bool(perms["process"]["spawn"]),
        "read_allowed": readable,
        "write_allowed": writable,
        "limits": dict(manifest.get("limits") or {}),
        "gui": manifest["interface"]["type"] == "gui",
        "enforce": MODE == "1",
    }


def write_policy(policy: dict, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(policy, f, sort_keys=True)
