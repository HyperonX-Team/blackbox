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
import time
from collections import deque
from pathlib import Path

from blackbox import platform as bb_platform
from blackbox.errors import BlackboxError
from blackbox.runtime.providers import get_provider
from blackbox.sandbox import jail
from blackbox.sandbox import limits as bb_limits
from blackbox.sandbox.policy import build_policy, write_policy
from blackbox.storage import paths

WEB_URL_RE = re.compile(r"127\.0\.0\.1:(\d{2,5})|localhost:(\d{2,5})")

# host env vars passed through to the package process (GUI + windows shell basics)
_GUI_ENV_POSIX = ["DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XAUTHORITY",
                  "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_TYPE"]
_GUI_ENV_WINDOWS = ["APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "COMSPEC"]


class RunContext:
    def __init__(self, manifest, *, app_dir, site_dir, runtime_exe, work_dir, triple):
        self.manifest = manifest
        self.app_dir = str(app_dir)
        self.site_dir = str(site_dir)
        self.runtime_exe = str(runtime_exe) if runtime_exe else None
        self.work_dir = str(work_dir)
        self.triple = triple
        self.data_dir = None      # persistent per-package data dir (blackbox run --data)
        self.log_file = None      # tee app output here (blackbox run --log)
        self.entry = None         # subcommand name from manifest.entrypoints
        self.secrets = None       # decrypted sealed secrets -> env
        self.sealed_error = None  # reason sealed secrets could not be opened

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
    for name in ("sitecustomize.py", "node_guard.js", "netmatch.py"):
        src = shim_src / name
        if not src.exists():
            continue
        dest_file = dest / name
        payload = src.read_bytes()
        if not dest_file.exists() or dest_file.read_bytes() != payload:
            dest_file.write_bytes(payload)
    return str(dest)


def build_launch(ctx: RunContext, extra_args=None, argv_override=None) -> dict:
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
        data_dir=ctx.data_dir,
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
    if ctx.data_dir:
        env["BLACKBOX_DATA"] = ctx.data_dir
    if is_win:
        env["SYSTEMROOT"] = os.environ.get("SystemRoot", r"C:\Windows")
        for k in _GUI_ENV_WINDOWS:
            if os.environ.get(k):
                env[k] = os.environ[k]
    elif m["interface"]["type"] == "gui":
        for k in _GUI_ENV_POSIX:
            if os.environ.get(k):
                env[k] = os.environ[k]
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
    if ctx.secrets:
        env.update(ctx.secrets)

    if argv_override is not None:
        argv = list(argv_override)
    else:
        ep = m["entrypoint"]
        if ctx.entry:
            sub = (m.get("entrypoints") or {}).get(ctx.entry)
            if not sub:
                avail = ", ".join(sorted(m.get("entrypoints") or {})) or "(none defined)"
                raise BlackboxError(f"Package '{m['name']}' has no subcommand '{ctx.entry}'.",
                                    try_hint=f"Available subcommands: {avail}")
            ep = sub
        argv = provider.resolve_command(ep["command"],
                                        list(ep["args"]) + list(extra_args or []),
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


def exec_interactive(ctx: RunContext, argv_override=None) -> int:
    """Run inside the package's environment with stdio attached (shell / dev)."""
    launch = build_launch(ctx, argv_override=argv_override)
    print(f"BLACKBOX: interactive [{launch['enforcement']}] — type 'exit' to leave.")
    try:
        return subprocess.call(launch["argv"], env=launch["env"], cwd=launch["cwd"])
    except KeyboardInterrupt:
        return 130


def _crash_bundle(ctx: RunContext, rc, tail):
    try:
        import json
        d = paths.home() / "logs"
        d.mkdir(parents=True, exist_ok=True)
        name = ctx.manifest["name"]
        p = d / f"crash-{name}-{int(time.time())}.json"
        p.write_text(json.dumps({
            "package": name, "version": ctx.manifest["version"], "exit_code": rc,
            "entry": ctx.entry, "triple": ctx.triple,
            "network": ctx.manifest["permissions"]["network"],
            "limits": ctx.manifest.get("limits") or {},
            "output_tail": list(tail)[-80:],
        }, indent=2), encoding="utf-8")
        print(f"BLACKBOX: wrote crash bundle {p}")
    except OSError:
        pass


def execute(ctx: RunContext, extra_args=None, *, quiet=False) -> int:
    launch = build_launch(ctx, extra_args)
    m = ctx.manifest
    if not quiet:
        print(f"BLACKBOX: running {m['name']} {m['version']} [{launch['enforcement']}]")
        if ctx.sealed_error:
            print(f"BLACKBOX: sealed secrets NOT loaded — {ctx.sealed_error}")
        elif ctx.secrets:
            print(f"BLACKBOX: sealed secrets loaded ({len(ctx.secrets)} variable(s))")
        lim = bb_limits.describe(m.get("limits") or {}, ctx.triple)
        if lim:
            print(f"BLACKBOX: {lim}")
        if m["interface"]["type"] == "web":
            print("BLACKBOX: waiting for the app's local server...")
        if m["interface"]["type"] == "gui" and bb_platform.target_info(ctx.triple)["os"] == "darwin" and not launch["jailed"]:
            print("BLACKBOX: note — GUI on macOS runs without sandbox-exec (WindowServer access "
                  "cannot be granted via profile); the runtime shim still enforces the contract.")

    limits = m.get("limits") or {}
    is_win = bb_platform.target_info(ctx.triple)["os"] == "windows"
    creation = subprocess.CREATE_SUSPENDED if (is_win and limits) else 0
    preexec = None if is_win else bb_limits.make_preexec(limits)
    proc = subprocess.Popen(launch["argv"], env=launch["env"], cwd=launch["cwd"],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, errors="replace",
                            creationflags=creation, preexec_fn=preexec)
    if creation:
        bb_limits.attach_windows_job(proc, limits)
        bb_limits.resume_windows(proc)

    log_f = None
    if ctx.log_file:
        try:
            os.makedirs(os.path.dirname(ctx.log_file), exist_ok=True)
            log_f = open(ctx.log_file, "a", encoding="utf-8", errors="replace")
            log_f.write(f"\n===== {m['name']} {m['version']} run @ {int(time.time())} =====\n")
        except OSError:
            log_f = None

    shown_url = False
    tail = deque(maxlen=120)
    try:
        for line in proc.stdout:
            tail.append(line.rstrip("\n"))
            sys.stdout.write(line)
            sys.stdout.flush()
            if log_f:
                log_f.write(line)
                log_f.flush()
            if m["interface"]["type"] == "web" and not shown_url:
                match = WEB_URL_RE.search(line)
                if match:
                    port = match.group(1) or match.group(2)
                    print(f"BLACKBOX: {m['name']} is live at  http://127.0.0.1:{port}")
                    shown_url = True
    except KeyboardInterrupt:
        proc.terminate()
    proc.wait()
    if log_f:
        log_f.close()
    rc = proc.returncode
    if rc not in (0, None):
        _crash_bundle(ctx, rc, tail)
    return 0 if rc is None else rc
