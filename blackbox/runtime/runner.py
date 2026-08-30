"""BLACKBOX run: assemble, isolate, execute.

A run composes:

    ~/.blackbox/runtimes/<type>/<ver>/<triple>/   shared, hash-verified interpreter
    ~/.blackbox/layers/<digest>/dependencies      shared dependency layer (CAS)
    ~/.blackbox/layers/<digest>/application       application layer (CAS)
    ~/.blackbox/sandbox-shim/                     Python in-process guard

with a scrubbed environment, the manifest permissions materialized as an
enforceable policy, and a platform jail where one exists. The host's own
Python/Node installation is never used or consulted.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

from blackbox import platform as bb_platform
from blackbox.errors import BlackboxError
from blackbox.runtime.providers import get_provider
from blackbox.sandbox import jail
from blackbox.sandbox.policy import build_policy, write_policy
from blackbox.storage import paths

WEB_URL_RE = re.compile(r"127\.0\.0\.1:(\d{2,5})|localhost:(\d{2,5})")


class RunContext:
    def __init__(self, manifest, *, app_dir, site_dir, runtime_exe, work_dir, triple):
        self.manifest = manifest
        self.app_dir = str(app_dir)
        self.site_dir = str(site_dir)
        self.runtime_exe = str(runtime_exe) if runtime_exe else None
        self.work_dir = str(work_dir)
        self.triple = triple

    @property
    def input_dir(self):
        return os.path.join(self.work_dir, "input")

    @property
    def output_dir(self):
        return os.path.join(self.work_dir, "output")


def _shim_dir() -> str:
    dest = paths.home() / "sandbox-shim"
    dest.mkdir(parents=True, exist_ok=True)
    shim_src = Path(__file__).resolve().parent.parent / "sandbox" / "shim"
    for name in ("sitecustomize.py", "node_guard.js"):
        src = shim_src / name
        if not src.exists():
            continue
        dest_file = dest / name
        payload = src.read_bytes()
        if not dest_file.exists() or dest_file.read_bytes() != payload:
            dest_file.write_bytes(payload)
    return str(dest)


def build_launch(ctx: RunContext, extra_args=None) -> dict:
    m = ctx.manifest
    rtype = m["runtime"]["type"]
    provider = get_provider(rtype)
    os.makedirs(ctx.input_dir, exist_ok=True)
    os.makedirs(ctx.output_dir, exist_ok=True)
    tmp_dir = os.path.join(ctx.work_dir, "_blackbox_tmp")
    os.makedirs(tmp_dir, exist_ok=True)

    triple = ctx.triple
    is_win = bb_platform.target_info(triple)["os"] == "windows"
    if rtype == "native":
        exe_dir = os.path.abspath(ctx.app_dir)
        runtime_root = exe_dir
    else:
        exe_dir = os.path.dirname(ctx.runtime_exe)
        runtime_root = exe_dir if is_win else os.path.dirname(exe_dir)
        runtime_root = os.path.realpath(runtime_root)

    use_shim = rtype in ("python", "node")  # languages with an in-process guard shim
    policy = build_policy(
        m,
        app_dir=ctx.app_dir,
        site_dir=ctx.site_dir or runtime_root,
        runtime_root=runtime_root,
        work_dir=ctx.work_dir,
        trusted_read=[_shim_dir()] if use_shim else [],
    )
    policy_path = os.path.join(ctx.work_dir, "_blackbox_policy.json")
    write_policy(policy, policy_path)

    path_dirs = [exe_dir] + ([r"%SystemRoot%\System32" if is_win else "/usr/bin" + os.pathsep + "/bin"])
    env = {
        "PATH": os.pathsep.join(path_dirs),
        "TMPDIR": tmp_dir,
        "TEMP": tmp_dir,
        "TMP": tmp_dir,
        "HOME": ctx.work_dir,
        "USERPROFILE": ctx.work_dir,
        "BLACKBOX_NAME": m["name"],
        "BLACKBOX_WORK": ctx.work_dir,
        "BLACKBOX_INPUT": ctx.input_dir,
        "BLACKBOX_OUTPUT": ctx.output_dir,
        "BLACKBOX_SANDBOX_POLICY": policy_path,
    }
    if is_win:
        env["SYSTEMROOT"] = os.environ.get("SystemRoot", r"C:\Windows")
    env.update(provider.env(ctx.runtime_exe, ctx.site_dir, ctx.app_dir, triple))
    if use_shim and env.get("PYTHONPATH"):
        env["PYTHONPATH"] = _shim_dir() + os.pathsep + env["PYTHONPATH"]
    elif rtype == "python":
        env["PYTHONPATH"] = _shim_dir()
    if rtype == "node":
        guard = os.path.join(_shim_dir(), "node_guard.js")
        if os.path.exists(guard):
            env["NODE_OPTIONS"] = (env.get("NODE_OPTIONS", "") + " --require " + guard).strip()
    env.update(m["environment"]["variables"])

    argv = provider.resolve_command(m["entrypoint"]["command"],
                                    list(m["entrypoint"]["args"]) + list(extra_args or []),
                                    ctx.runtime_exe, ctx.app_dir)

    wrapped, jailed = jail.wrap_command(
        argv, policy=policy,
        jail_roots=[runtime_root, exe_dir] + ([ctx.site_dir] if ctx.site_dir else [])
        + [ctx.app_dir] + ([_shim_dir()] if use_shim else []),
        network_enabled=m["permissions"]["network"]["enabled"],
        work_dir=ctx.work_dir,
    )
    tiers = (["platform jail"] if jailed else []) + (["runtime shim"] if use_shim else [])
    if not tiers:
        tiers = ["environment isolation only"]
    return {"argv": wrapped, "env": env, "cwd": ctx.work_dir, "jailed": jailed,
            "policy": policy, "enforcement": " + ".join(tiers)}


def execute(ctx: RunContext, extra_args=None, *, quiet=False) -> int:
    launch = build_launch(ctx, extra_args)
    m = ctx.manifest
    if not quiet:
        print(f"BLACKBOX: running {m['name']} {m['version']} [{launch['enforcement']}]")
        if m["interface"]["type"] == "web":
            print("BLACKBOX: waiting for the app's local server...")
    proc = subprocess.Popen(launch["argv"], env=launch["env"], cwd=launch["cwd"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace")
    shown_url = False
    try:
        for line in proc.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
            if m["interface"]["type"] == "web" and not shown_url:
                match = WEB_URL_RE.search(line)
                if match:
                    port = match.group(1) or match.group(2)
                    print(f"BLACKBOX: {m['name']} is live at  http://127.0.0.1:{port}")
                    shown_url = True
    except KeyboardInterrupt:
        proc.terminate()
    proc.wait()
    return proc.returncode
