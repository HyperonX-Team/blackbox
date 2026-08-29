"""Dependency resolution and locking for Python BLACKBOXes.

Strategy (documented in docs/architecture.md):
  lock:  `pip install --dry-run --report` against the *target* interpreter /
         platform, so a Linux package locks Linux wheels even when built on
         Windows. Produces blackbox.lock with exact versions, URLs and hashes.
  fetch: wheels are downloaded directly from the recorded URLs, verified
         against their recorded sha256, and installed with
         `pip install --no-index --find-links <wheels> --target <site>`.
         The resulting site-packages tree is one deterministic,
         content-addressed dependency layer.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

from blackbox import deterministic
from blackbox.errors import BlackboxError
from blackbox.platform import pip_target_flags
from blackbox.storage.cas import CAS

WHEEL_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.]+)-(?P<version>[A-Za-z0-9_.!+]+)-")

FROZEN = bool(getattr(sys, "frozen", False))  # running inside a PyInstaller binary


def run_pip(args, capture=True) -> subprocess.CompletedProcess:
    """Run pip either as a subprocess (normal install) or in-process (frozen CLI).

    A PyInstaller 'blackbox' exe must not re-invoke itself via sys.executable,
    so pip is bundled into the binary and driven in-process there.
    """
    if not FROZEN:
        cmd = [sys.executable, "-m", "pip", *args]
        return subprocess.run(cmd, capture_output=True, text=True)
    import contextlib
    import io

    import pip
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = pip.main(args)
    return subprocess.CompletedProcess(["pip", *args], rc, out.getvalue(), err.getvalue())


def lock_requirements(requirements, python_version, target_triple) -> dict:
    reqs = [r.strip() for r in requirements if r.strip() and not r.strip().startswith("#")]
    lock = {"lock_version": 1,
            "runtime": {"type": "python", "version": python_version, "target": target_triple},
            "packages": []}
    if not reqs:
        return lock

    with tempfile.TemporaryDirectory(prefix="blackbox-lock-") as td:
        req_file = os.path.join(td, "requirements.txt")
        with open(req_file, "w", encoding="utf-8") as f:
            f.write("\n".join(reqs) + "\n")
        report_file = os.path.join(td, "report.json")
        pip_args = [
            "install", "--dry-run", "--ignore-installed", "--disable-pip-version-check",
            "--target", os.path.join(td, "resolve-only"),
            "--report", report_file, "--only-binary", ":all:", "-r", req_file,
        ] + pip_target_flags(target_triple, python_version)
        proc = run_pip(pip_args)
        if proc.returncode != 0:
            raise BlackboxError(
                "Could not resolve the requested dependencies.",
                detail=_tail(proc.stderr) or _tail(proc.stdout),
                try_hint=[
                    "Check the version pins in requirements.txt.",
                    "Confirm the packages publish wheels for "
                    + f"Python {python_version} on {target_triple} (source-only packages are not supported).",
                ],
            )
        with open(report_file, encoding="utf-8") as f:
            report = json.load(f)

    for item in report.get("install", []):
        meta = item.get("metadata", {})
        url = (item.get("download_info") or {}).get("url")
        hashes = ((item.get("download_info") or {}).get("archive_info") or {}).get("hashes") or {}
        sha = hashes.get("sha256")
        name = meta.get("name", "")
        version = meta.get("version", "")
        lock["packages"].append({
            "name": name.lower().replace("_", "-"),
            "version": version,
            "url": url,
            "sha256": sha,
        })
    lock["packages"].sort(key=lambda p: p["name"])
    return lock


def fetch_locked(lock: dict, cas: CAS) -> str:
    """Download every locked wheel, verify its hash, store in CAS. Returns wheels dir path."""
    wheels_dir = os.path.join(tempfile.mkdtemp(prefix="blackbox-wheels-"), "wheels")
    os.makedirs(wheels_dir)
    for pkg in lock["packages"]:
        if not pkg.get("url") or not pkg.get("sha256"):
            raise BlackboxError(
                f"Lockfile entry for '{pkg['name']}' is incomplete (missing url or sha256).",
                try_hint="Delete blackbox.lock and run 'blackbox pack' again to regenerate it.",
            )
        filename = pkg["url"].split("/")[-1].split("#")[0]
        ref = "sha256:" + pkg["sha256"]
        need_download = True
        try:
            obj = cas.get_path(ref)
            need_download = not cas.verify(ref)  # self-heal corrupted cache objects
            if need_download:
                cas.delete(ref)
        except BlackboxError:
            obj = None
        if need_download:
            data = _download(pkg["url"])
            if deterministic.sha256_bytes(data) != pkg["sha256"]:
                raise BlackboxError(
                    f"Downloaded '{pkg['name']}' does not match the hash recorded in the lockfile.",
                    detail=f"URL: {pkg['url']}",
                    try_hint="The package may have been tampered with upstream. Aborting.",
                )
            cas.put_bytes(data)
            obj = cas.get_path(ref)
        dest = os.path.join(wheels_dir, filename)
        with open(obj, "rb") as src, open(dest, "wb") as dst:
            dst.write(src.read())
    return wheels_dir


def build_site_packages(lock: dict, wheels_dir: str) -> dict:
    """Expand locked wheels into an isolated site-packages tree. Returns {arcname: bytes}.

    Wheels are zips; BLACKBOX apps import via PYTHONPATH, so pip's install
    machinery (and console-script generation) is unnecessary — and avoiding it
    keeps this function working inside the frozen standalone CLI.
    """
    import zipfile

    site = tempfile.mkdtemp(prefix="blackbox-site-")
    try:
        for fn in sorted(os.listdir(wheels_dir)):
            if not fn.endswith(".whl"):
                continue
            with zipfile.ZipFile(os.path.join(wheels_dir, fn)) as zf:
                for info in zf.infolist():
                    name = info.filename.replace("\\", "/")
                    if name.endswith("/"):
                        os.makedirs(os.path.join(site, name), exist_ok=True)
                        continue
                    target = os.path.realpath(os.path.join(site, name))
                    if not target.startswith(os.path.realpath(site) + os.sep):
                        raise BlackboxError(f"Wheel '{fn}' contains an unsafe path: {name}")
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, "wb") as out:
                        out.write(zf.read(info))
        files, _execs = deterministic.collect_tree(site)
        # pip stamps the build-time temp wheel path into direct_url.json; that is
        # the only machine-specific byte in the tree. Stripping it makes the layer
        # content identical across machines -> identical digest -> deduplication.
        # (Our expansion never creates it; RECORD is stripped for the same reason.)
        files = {k: v for k, v in files.items()
                 if not (k.endswith(".dist-info/direct_url.json") or k.endswith("/RECORD"))}
        return files
    finally:
        shutil.rmtree(site, ignore_errors=True)


def deps_digest(lock: dict) -> str:
    """Stable identity of a dependency set: the sorted wheel hashes."""
    canon = json.dumps([{"name": p["name"], "sha256": p["sha256"]} for p in lock["packages"]], sort_keys=True)
    return "sha256:" + deterministic.sha256_bytes(canon.encode())


def _download(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=60) as r:
            return r.read()
    except OSError as e:
        raise BlackboxError(
            f"Could not download {url}",
            detail=str(e),
            try_hint=[
                "BLACKBOX needs one-time network access to fetch locked dependencies.",
                "If the dependency is already cached, no network is required.",
            ],
        )


def _tail(text, n=15) -> str:
    lines = [ln for ln in (text or "").strip().splitlines() if ln.strip()]
    return "\n".join(lines[-n:])


def requirements_from_lock(lock: dict) -> list:
    return [f"{p['name']}=={p['version']}" for p in lock["packages"]]


# ---------------------------------------------------------------- node

def node_lock(package_json_path: str, install_dir: str) -> dict:
    """npm install into an isolated dir; return lock dict derived from the package-lock."""
    import shutil

    shutil.copy(package_json_path, os.path.join(install_dir, "package.json"))
    npm = "npm.cmd" if os.name == "nt" else "npm"
    proc = subprocess.run(
        [npm, "install", "--omit=dev", "--no-audit", "--no-fund", "--loglevel=error", "--ignore-scripts"],
        cwd=install_dir, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise BlackboxError(
            "npm could not resolve the dependencies in package.json.",
            detail=_tail(proc.stderr) or _tail(proc.stdout),
            try_hint="Check the version pins in package.json.",
        )
    lock = {"packages": [], "node_modules": True}
    plock_path = os.path.join(install_dir, "package-lock.json")
    if os.path.isfile(plock_path):
        with open(plock_path, encoding="utf-8") as f:
            plock = json.load(f)
        for pkg, meta in sorted((plock.get("packages") or {}).items()):
            if not pkg or pkg == "node_modules/" or not meta.get("version"):
                continue  # root entry
            name = pkg.split("node_modules/")[-1]
            lock["packages"].append({
                "name": name, "version": meta["version"],
                "integrity": meta.get("integrity", ""),
            })
        lock["packages"].sort(key=lambda p: p["name"])
    return lock


def node_site_files(install_dir: str):
    files, execs = deterministic.collect_tree(install_dir)
    return files, execs
