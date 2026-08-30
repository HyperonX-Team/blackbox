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
    # sandbox-exec profiles cannot grant WindowServer access, so a GUI package
    # on macOS would render nothing inside the jail; run it jailed-off (the
    # runtime shim still enforces the permission contract) and let the runner
    # print the explanatory note.
    if policy.get("gui") and bb_platform.os_name() == "macos":
        return argv, False
    if cap == "bwrap":
        return _bwrap(argv, policy, network_enabled, work_dir), True
    if cap == "sandbox-exec":
        return _sandbox_exec(argv, policy, network_enabled, work_dir), True
    return argv, False


def _bwrap(argv, policy, network_enabled, work_dir):
    # Per docs/security.md: start from a read-only view of the host, then make
    # ONLY the granted write paths (+ the package tmp) writable. Reads of the
    # host filesystem are not restricted in the MVP (a fully-allowlisted bind
    # set starved the provisioned runtimes of system paths on CI); writes and
    # network are the enforced tiers here, reads via the runtime shim contract.
    args = ["bwrap", "--die-with-parent", "--new-session",
            "--unshare-user", "--unshare-pid", "--unshare-ipc", "--unshare-cgroup"]
    if not network_enabled:
        args.append("--unshare-net")
    args += ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    # Writable paths (bind after the read-only root so writes take precedence).
    for w in policy["write_allowed"]:
        if os.path.isdir(w):
            args += ["--bind", w, w]
    # GUI appliances need the display sockets + GPU device nodes; these are
    # bound writable because X11/Wayland clients write to their sockets.
    if policy.get("gui"):
        for d in ("/tmp/.X11-unix", "/dev/shm", "/dev/dri"):
            if os.path.isdir(d):
                args += ["--bind", d, d]
        uid_dir = f"/run/user/{os.getuid()}" if hasattr(os, "getuid") else None
        if uid_dir and os.path.isdir(uid_dir):
            args += ["--bind", uid_dir, uid_dir]
    work = os.path.realpath(str(work_dir))
    args += ["--bind", work, work]
    args += ["--chdir", work, "--", *argv]
    return args


def _sandbox_exec(argv, policy, network_enabled, work_dir):
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny file-write*)",
    ]
    for w in policy["write_allowed"]:
        lines.append(f'(allow file-write* (subpath "{w}"))')
    work = os.path.realpath(str(work_dir))
    lines.append(f'(allow file-write* (subpath "{work}"))')
    if not network_enabled:
        lines.append("(deny network*)")
    profile = "\n".join(lines)
    return ["sandbox-exec", "-p", profile, *argv]
