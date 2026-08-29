"""Runtime providers: the extension point for every language BLACKBOX supports.

A provider knows three things:
  * how to PROVISION an interpreter for a target platform (verified by hash)
  * how to LOCK dependencies at pack time (optional)
  * how to SHAPE the execution environment for `blackbox run`

Adding a language means adding a provider - nothing else in the system
changes. The MVP ships:

    python  -> python-build-standalone (pinned releases, sha256-verified)
    node    -> nodejs.org official distributions (version+sha256 pinned in the lockfile)
    native  -> the package carries its own compiled executable (Rust, Go, C, ...)

Future providers can cover R, Julia, WASM (via a bundled interpreter or a
compiled core) without touching the package format: the manifest's runtime
block is the only contract.
"""

import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile

from blackbox import platform as bb_platform
from blackbox.deterministic import sha256_bytes, sha256_file
from blackbox.errors import BlackboxError, RuntimeMissingError
from blackbox.storage import paths

NODE_INDEX = "https://nodejs.org/dist/index.json"
NODE_DIST = "https://nodejs.org/dist"
NODE_MAJOR_MAP = {"18": "Hydrogen", "20": "Iron", "22": "Jod", "24": "Krypton"}


def _download(url, timeout=120) -> bytes:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def _extractall(tf, dest):
    """tarfile.extractall with the 'data' filter when available (3.12+/patched stdlib).

    We already pre-validate member paths for traversal, so 'data' is belt-and-suspenders;
    passing it explicitly future-proofs for 3.14's default change.
    """
    try:
        return tf.extractall(dest, filter="data")
    except TypeError:
        return tf.extractall(dest)


class Provider:
    type = ""

    def supports(self, version: str) -> bool:
        raise NotImplementedError

    def pin_for_lock(self, version: str, target: str) -> dict:
        """Pack-time: record exact interpreter identity in blackbox.lock."""
        return {}

    def ensure(self, version: str, target: str, *, pin: dict = None, quiet=False):
        """Provision the interpreter; return its executable path (None for native)."""
        raise NotImplementedError

    def env(self, exe: str, site_dir: str, app_dir: str, target: str) -> dict:
        return {}

    def resolve_command(self, command: str, args: list, exe: str, app_dir: str):
        raise NotImplementedError

    def _check_target(self, target: str):
        here = bb_platform.current_triple()
        a, b = bb_platform.target_info(here), bb_platform.target_info(target)
        if a["os"] != b["os"] or a["arch"] != b["arch"]:
            raise RuntimeMissingError(
                f"This package targets {target}, but this machine is {here}.",
                try_hint="BLACKBOX cannot execute foreign-architecture binaries. Run on a matching machine.",
            )


# ---------------------------------------------------------------- python

class PythonProvider(Provider):
    type = "python"
    PBS_BASE = "https://github.com/astral-sh/python-build-standalone/releases/download"
    PINNED = {"3.11": ("3.11.10", "20241002"), "3.12": ("3.12.7", "20241002"), "3.13": ("3.13.0", "20241002")}

    def supports(self, version):
        return version in self.PINNED

    def _dir(self, version, target):
        return os.path.join(str(paths.home() / "runtimes"), "python", version, target)

    def executable(self, version, target):
        root = self._dir(version, target)
        py = bb_platform.exe("python", target)
        if bb_platform.target_info(target)["os"] == "windows":
            return os.path.join(root, "python", py)
        return os.path.join(root, "python", "bin", py)

    def is_installed(self, version, target):
        return os.path.isfile(self.executable(version, target))

    def ensure(self, version, target, *, pin=None, quiet=False):
        self._check_target(target)
        if not self.supports(version):
            raise RuntimeMissingError(f"No pinned runtime for Python {version}.",
                                      try_hint="Supported: " + ", ".join(sorted(self.PINNED)))
        exe_path = self.executable(version, target)
        if os.path.isfile(exe_path):
            return exe_path
        full, tag = self.PINNED[version]
        asset = f"cpython-{full}+{tag}-{target}-install_only.tar.gz"
        url = f"{self.PBS_BASE}/{tag}/{asset}"
        if not quiet:
            print(f"BLACKBOX: provisioning Python {full} runtime (first use only, ~25 MB)...")
        try:
            expected = _download(url + ".sha256", 30).decode().split()[0]
            data = _download(url, timeout=600)
        except OSError as e:
            raise RuntimeMissingError(
                f"Package requires Python {version} runtime, but it is not cached and could not be downloaded.",
                detail=f"Attempted:\n  {self._dir(version, target)}\nError: {e}",
                try_hint=["Check your network connection and retry.",
                          "Or seed offline: blackbox runtime import <tarball>",
                          "blackbox doctor"],
            )
        if sha256_bytes(data) != expected:
            raise RuntimeMissingError("Downloaded Python runtime failed integrity verification.",
                                      detail=f"expected {expected}",
                                      try_hint="Refusing to install. Retry, or run 'blackbox doctor'.")
        self._extract(data, self._dir(version, target))
        if not os.path.isfile(exe_path):
            raise RuntimeMissingError("Runtime extraction completed but the interpreter is missing.",
                                      detail=exe_path)
        return exe_path

    def _extract(self, blob: bytes, dest):
        dest = os.path.abspath(dest)
        staged = dest + ".staging"
        shutil.rmtree(staged, ignore_errors=True)
        os.makedirs(staged)
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            for m in tf.getmembers():
                member = os.path.normpath(m.name)
                if member.startswith(("..", "/")) or os.path.isabs(member):
                    raise RuntimeMissingError("Runtime archive contains an unsafe path.", detail=m.name)
            _extractall(tf, staged)
        if os.path.exists(dest):
            shutil.rmtree(dest)
        os.replace(staged, dest)

    def env(self, exe, site_dir, app_dir, target):
        env = {"PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        if site_dir:
            env["PYTHONPATH"] = site_dir + os.pathsep + app_dir
        return env

    def resolve_command(self, command, args, exe, app_dir):
        if command not in ("python", "python3", "py"):
            raise BlackboxError(f"Python packages must use entrypoint command 'python' (got '{command}').")
        script = None
        if args:
            cand = os.path.normpath(os.path.join(app_dir, args[0]))
            if cand.startswith(os.path.abspath(app_dir) + os.sep) and os.path.isfile(cand):
                script = cand
        return [exe, "-u", script or (args[0] if args else ""), *args[1:]] if args else [exe]


# ---------------------------------------------------------------- node

class NodeProvider(Provider):
    type = "node"
    SUPPORTED_MAJORS = set(NODE_MAJOR_MAP)

    def supports(self, version):
        return version in NODE_MAJOR_MAP

    def _dir(self, version, target):
        return os.path.join(str(paths.home() / "runtimes"), "node", version, target)

    @staticmethod
    def _dist_names(target):
        info = bb_platform.target_info(target)
        osmap = {"windows": "win", "linux": "linux", "macos": "darwin"}
        archmap = {"x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}
        base = f"node-{{ver}}-{osmap[info['os']]}-{archmap[info['arch']]}"
        if info["os"] == "windows":
            return base.format(ver="{ver}") + ".zip", base
        return base.format(ver="{ver}") + ".tar.gz", base

    def pin_for_lock(self, version, target):
        if not self.supports(version):
            raise BlackboxError(f"Node major version '{version}' is not supported. "
                                f"Supported: {', '.join(sorted(NODE_MAJOR_MAP))}")
        index = json.loads(_download(NODE_INDEX, timeout=60))
        entry = next((e for e in index if e["version"].split(".")[0][1:] == version and e.get("lts")), None)
        if entry is None:
            raise BlackboxError(f"No LTS release line found for Node {version}.")
        exact = entry["version"]  # e.g. "v22.14.0"
        fname, _ = self._dist_names(target)
        asset = fname.format(ver=exact)
        shasums = _download(f"{NODE_DIST}/{exact}/SHASUMS256.txt", timeout=60).decode()
        sha = next(ln.split()[0] for ln in shasums.splitlines() if ln.split()[-1] == asset)
        return {"version": exact.lstrip("v"), "asset": asset,
                "url": f"{NODE_DIST}/{exact}/{asset}", "sha256": sha}

    def _exe(self, verdir, target):
        node = bb_platform.exe("node", target)
        return os.path.join(verdir, node) if bb_platform.target_info(target)["os"] == "windows" \
            else os.path.join(verdir, "bin", node)

    def is_installed(self, version, target):
        root = self._dir(version, target)
        if not os.path.isdir(root):
            return False
        for d in os.listdir(root):
            if os.path.isfile(self._exe(os.path.join(root, d), target)):
                return True
        return False

    def ensure(self, version, target, *, pin=None, quiet=False):
        self._check_target(target)
        if not pin:
            pin = self.pin_for_lock(version, target)
        root = self._dir(version, target)
        inner = pin["asset"].rsplit(".", 2)[0] if pin["asset"].endswith(".tar.gz") else pin["asset"].rsplit(".", 1)[0]
        verdir = os.path.join(root, inner)
        exe = self._exe(verdir, target)
        if os.path.isfile(exe):
            return exe
        if not quiet:
            print(f"BLACKBOX: provisioning Node.js {pin['version']} runtime (first use only, ~25 MB)...")
        try:
            data = _download(pin["url"], timeout=600)
        except OSError as e:
            raise RuntimeMissingError(
                f"Package requires Node.js {version}, but it is not cached and could not be downloaded.",
                detail=f"Error: {e}", try_hint=["Retry with network, or run: blackbox doctor"])
        if sha256_bytes(data) != pin["sha256"]:
            raise RuntimeMissingError("Downloaded Node runtime failed integrity verification.",
                                      detail=f"expected {pin['sha256']}",
                                      try_hint="Refusing to install. The upstream artifact changed?")
        os.makedirs(root, exist_ok=True)
        if pin["asset"].endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(root)  # archive's own top-level dir becomes verdir
        else:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                for m in tf.getmembers():
                    member = os.path.normpath(m.name)
                    if member.startswith(("..", "/")) or os.path.isabs(member):
                        raise RuntimeMissingError("Runtime archive contains an unsafe path.", detail=m.name)
                _extractall(tf, root)
        if not os.path.isfile(exe):
            raise RuntimeMissingError("Node extraction completed but the interpreter is missing.", detail=exe)
        return exe

    def env(self, exe, site_dir, app_dir, target):
        env = {}
        if site_dir:
            env["NODE_PATH"] = os.path.join(site_dir, "node_modules")
        return env

    def resolve_command(self, command, args, exe, app_dir):
        if command != "node":
            raise BlackboxError(f"Node packages must use entrypoint command 'node' (got '{command}').")
        script = None
        if args:
            cand = os.path.normpath(os.path.join(app_dir, args[0]))
            if cand.startswith(os.path.abspath(app_dir) + os.sep) and os.path.isfile(cand):
                script = cand
        if not script and args:
            raise BlackboxError(f"Entrypoint script '{args[0]}' not found in the application layer.")
        return [exe, script or args[0], *args[1:]]


# ---------------------------------------------------------------- native

class NativeProvider(Provider):
    """The package ships its own compiled executable (Rust, Go, C, ...).

    The entrypoint command must be a path inside the application layer,
    e.g. ./bin/server. There is no interpreter to provision; the runtime
    layer of a native BLACKBOX is the binary itself, already content-addressed
    inside the application layer.
    """
    type = "native"

    def supports(self, version):
        return True

    def ensure(self, version, target, *, pin=None, quiet=False):
        self._check_target(target)
        return None

    def env(self, exe, site_dir, app_dir, target):
        return {}

    def resolve_command(self, command, args, exe, app_dir):
        if not command.startswith("./"):
            raise BlackboxError(
                "Native packages must point the entrypoint at a bundled executable, e.g. command: ./bin/app",
                detail=f"Got command: {command}")
        cand = os.path.normpath(os.path.join(app_dir, command[2:]))
        if not cand.startswith(os.path.abspath(app_dir) + os.sep) or not os.path.isfile(cand):
            raise BlackboxError(f"Native entrypoint '{command}' was not found in the application layer.",
                                try_hint="Compile the binary for this target and re-pack (binaries are platform-specific).")
        if os.name != "nt":
            os.chmod(cand, 0o755)
        return [cand, *args]


PROVIDERS = {p.type: p() for p in (PythonProvider, NodeProvider, NativeProvider)}


def get_provider(rtype: str) -> Provider:
    if rtype not in PROVIDERS:
        raise BlackboxError(f"No BLACKBOX runtime provider for '{rtype}'.",
                            detail="Available: " + ", ".join(sorted(PROVIDERS)),
                            try_hint="See docs/architecture.md for how providers are added.")
    return PROVIDERS[rtype]
