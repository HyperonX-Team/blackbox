"""BLACKBOX runtime sandbox shim.

Loaded automatically as `sitecustomize` inside a BLACKBOX application process.
It reads a JSON policy from $BLACKBOX_SANDBOX_POLICY and enforces:

  * network access  - connect() to non-loopback addresses is denied when the
    package did not request network permission
  * process spawning - subprocess/os.exec*/os.system are denied unless allowed
  * filesystem writes - open() for writing outside the allowed roots raises

This is an in-process guard: it catches accidents and enforces the permission
contract, and it is always combined with platform-level isolation where the
OS supports it. It is NOT a kernel security boundary on its own.
"""

import json
import os
import socket
import sys

_POLICY_PATH = os.environ.get("BLACKBOX_SANDBOX_POLICY")
POLICY = {"network": False, "spawn": False, "read_allowed": [], "write_allowed": [], "enforce": True}

if _POLICY_PATH and os.path.isfile(_POLICY_PATH):
    with open(_POLICY_PATH, encoding="utf-8") as _f:
        POLICY.update(json.load(_f))

_LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class SandboxViolation(RuntimeError):
    pass


def _violation(kind, target, hint):
    msg = (
        "\nBLACKBOX SANDBOX VIOLATION\n"
        f"  This package attempted {kind} which its manifest does not permit:\n"
        f"    {target}\n"
        f"  {hint}\n"
    )
    print(msg, file=sys.stderr)
    sys.stderr.flush()
    return SandboxViolation(msg.strip())


_real_excepthook = sys.excepthook


def _excepthook(etype, value, tb):
    if isinstance(value, SandboxViolation):
        sys.exit(76)  # message already printed; a traceback would be noise
    _real_excepthook(etype, value, tb)


sys.excepthook = _excepthook


def _allowed(path, roots):
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    return any(real == r or real.startswith(r + os.sep) for r in roots)


_orig_socket_init = socket.socket.__init__
_orig_create_connection = socket.create_connection


def _connect_guard(self, address, *a, **kw):
    if not POLICY["network"]:
        host = address[0] if isinstance(address, tuple) else address
        if self.family in (socket.AF_INET, socket.AF_INET6) and str(host) not in _LOOPBACK:
            raise _violation("outbound network access", f"{host}",
                             "Enable it in blackbox.yaml under permissions.network.enabled and re-pack.")
    return _orig_connect(self, address, *a, **kw)


try:
    _orig_connect = socket.socket.connect
    socket.socket.connect = _connect_guard
    socket.socket.connect_ex = lambda self, address, *a, **kw: _connect_guard(self, address, *a, **kw) or 0
except Exception:
    pass


def _guarded_create_connection(address, *args, **kwargs):
    host = address[0]
    if not POLICY["network"] and str(host) not in _LOOPBACK:
        raise _violation("outbound network access", f"{host}", "Network permission is disabled for this package.")
    return _orig_create_connection(address, *args, **kwargs)


socket.create_connection = _guarded_create_connection


def _guard_spawn(what):
    if not POLICY["spawn"] and POLICY["enforce"]:
        raise _violation("process spawning", what,
                         "Enable it in blackbox.yaml under permissions.process.spawn and re-pack.")


_orig_popen_init = None
try:
    import subprocess

    _orig_popen_init = subprocess.Popen.__init__

    def _popen_init(self, args=None, *a, **kw):
        _guard_spawn(str(args))
        return _orig_popen_init(self, args, *a, **kw)

    subprocess.Popen.__init__ = _popen_init
except Exception:
    pass

for _fn in ("system", "popen", "execv", "execve", "execvp", "spawnv", "spawnl"):
    _orig = getattr(os, _fn, None)
    if _orig is None:
        continue

    def _make(orig, name):
        def wrapper(*a, **kw):
            _guard_spawn(f"os.{name}({a[0] if a else ''})")
            return orig(*a, **kw)
        return wrapper

    setattr(os, _fn, _make(_orig, _fn))

_orig_open = open


def _safe_open(file, mode="r", *args, **kwargs):
    writing = isinstance(mode, str) and ("+" in mode or any(c in mode for c in "wax"))
    if POLICY["enforce"] and writing:
        target = file if isinstance(file, (str, bytes, os.PathLike)) else getattr(file, "name", None)
        if target is not None and isinstance(target, (str, bytes)):
            if isinstance(target, bytes):
                target = os.fsdecode(target)
            if not _allowed(target, POLICY["write_allowed"]):
                raise _violation("filesystem write", target,
                                 "Add this path to permissions.filesystem.write (relative to the package) and re-pack.")
    return _orig_open(file, mode, *args, **kwargs)


try:
    import builtins

    builtins.open = _safe_open
except Exception:
    pass
