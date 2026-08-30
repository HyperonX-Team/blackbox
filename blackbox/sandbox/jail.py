"""Platform-native isolation backends.

`wrap_command()` returns (argv, ok). ok=False means the platform jail is
unavailable; the runner then relies on the in-process shim + environment
scrubbing and labels the run accordingly. We never claim more isolation
than the OS gave us - capability is PROBED (bwrap can exist but be blocked
by the environment), not assumed.
"""

import os
import shutil
import subprocess

from blackbox import platform as bb_platform

_CACHE = {}


def _probe(key, argv):
    if key not in _CACHE:
        try:
            p = subprocess.run(argv, capture_output=True, timeout=20)
            _CACHE[key] = p.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            _CACHE[key] = False
    return _CACHE[key]


def capability() -> str:
    """One of: bwrap, sandbox-exec, shim-only."""
    osname = bb_platform.os_name()
    if osname == "linux" and shutil.which("bwrap"):
        if _probe("bwrap", ["bwrap", "--ro-bind", "/", "/", "--dev", "/dev",
                            "--proc", "/proc", "--unshare-user", "--unshare-pid", "--true"]):
            return "bwrap"
        return "shim-only"
    if osname == "macos" and shutil.which("sandbox-exec"):
        if _probe("sandbox-exec", ["sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true"]):
            return "sandbox-exec"
        return "shim-only"
    return "shim-only"


def wrap_command(argv, *, policy, jail_roots, network_enabled, work_dir):
    cap = capability()
    if cap == "bwrap":
        return _bwrap(argv, policy, network_enabled, work_dir), True
    if cap == "sandbox-exec":
        return _sandbox_exec(argv, policy, network_enabled, work_dir), True
    return argv, False


def _bwrap(argv, policy, network_enabled, work_dir):
    # Hardened profile: do not expose the whole host. We mount only the
    # runtime, application, dependency layers, manifest-granted read paths,
    # and the tiny set of system directories a Python/Node binary needs.
    # All read binds are explicit; all write binds come after so they remain
    # writable even if a path also appears in the read allowlist.
    args = ["bwrap", "--die-with-parent", "--new-session",
            "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-cgroup"]
    if not network_enabled:
        args.append("--unshare-net")

    # System locations required for dynamically-linked runtimes.
    for d in ("/etc", "/usr", "/lib", "/lib64", "/bin", "/sbin"):
        if os.path.isdir(d):
            args += ["--ro-bind", d, d]
    args += ["--dev", "/dev", "--proc", "/proc"]

    # Explicit read allowlist (runtime, app, site, shim, declared reads).
    seen = set()
    for r in policy["read_allowed"]:
        if r and r not in seen and os.path.exists(r):
            seen.add(r)
            args += ["--ro-bind", r, r]

    # Writable paths (bind after reads so writes take precedence).
    for w in policy["write_allowed"]:
        if os.path.isdir(w):
            args += ["--bind", w, w]
    work = os.path.realpath(str(work_dir))
    args += ["--bind", work, work]
    args += ["--chdir", work, "--", *argv]
    return args


def _sandbox_exec(argv, policy, network_enabled, work_dir):
    lines = [
        "(version 1)",
        "(deny file-read*)",
        "(deny file-write*)",
    ]
    seen = set()
    for path in list(policy["read_allowed"]) + [os.path.realpath(str(work_dir))]:
        if path and path not in seen:
            seen.add(path)
            lines.append(f'(allow file-read* (subpath "{path}"))')
    for w in policy["write_allowed"]:
        lines.append(f'(allow file-write* (subpath "{w}"))')
    work = os.path.realpath(str(work_dir))
    lines.append(f'(allow file-write* (subpath "{work}"))')
    if not network_enabled:
        lines.append("(deny network*)")
    profile = "\n".join(lines)
    return ["sandbox-exec", "-p", profile, *argv]
