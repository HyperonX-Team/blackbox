"""blackbox pack: source directory -> deterministic .blackbox file."""

import io
import os
import tempfile
import zipfile

import yaml

from blackbox import __version__, deterministic
from blackbox import platform as bb_platform
from blackbox.dependency import resolver
from blackbox.errors import BlackboxError
from blackbox.manifest import load_manifest
from blackbox.packaging import format as fmt
from blackbox.runtime.providers import get_provider
from blackbox.storage.cas import CAS

MANIFEST_NAME = "blackbox.yaml"
EXCLUDE_AT_PACK = ["output", "input", ".blackbox", "__pycache__", "blackbox.lock", "node_modules"]


def load_source(source_dir):
    mpath = os.path.join(str(source_dir), MANIFEST_NAME)
    if not os.path.isfile(mpath):
        raise BlackboxError(
            f"No {MANIFEST_NAME} found in {os.path.abspath(str(source_dir))}.",
            detail="A BLACKBOX project directory must contain a blackbox.yaml manifest.",
            try_hint="blackbox init myproject   # creates a starter project",
        )
    manifest = load_manifest(open(mpath, encoding="utf-8").read())
    return manifest


def read_requirements(source_dir, manifest):
    req_path = os.path.join(str(source_dir), manifest["requirements"])
    if not os.path.isfile(req_path):
        return []
    lines = [ln.strip() for ln in open(req_path, encoding="utf-8").read().splitlines()]
    return [ln for ln in lines if ln and not ln.startswith("#")]


def build_lock(source_dir, manifest, *, provider, reuse_existing=True):
    """Resolve dependencies + pin the interpreter identity into a lock dict."""
    rt = manifest["runtime"]
    lock = {"lock_version": 1, "runtime": {"type": rt["type"], "version": rt["version"],
                                           "target": rt["target"]}, "packages": []}
    if rt["type"] == "python":
        reqs = read_requirements(source_dir, manifest)
        lock_path = os.path.join(source_dir, "blackbox.lock")
        existing = None
        if reuse_existing and os.path.isfile(lock_path):
            try:
                existing = yaml.safe_load(open(lock_path, encoding="utf-8"))
            except yaml.YAMLError:
                existing = None
        if existing and _lock_still_valid(existing, reqs, rt):
            lock = existing
        else:
            lock = resolver.lock_requirements(reqs, rt["version"], rt["target"])
            with open(lock_path, "w", encoding="utf-8") as f:
                yaml.safe_dump(lock, f, sort_keys=True)
    elif rt["type"] == "node":
        lock["runtime"].update(provider.pin_for_lock(rt["version"], rt["target"]))
        pj = os.path.join(source_dir, manifest["requirements"])
        if os.path.isfile(pj):
            with tempfile.TemporaryDirectory(prefix="blackbox-npm-") as instdir:
                nlock = resolver.node_lock(pj, instdir)
                lock["packages"] = nlock["packages"]
                if nlock["packages"]:
                    site_files, site_execs = resolver.node_site_files(instdir)
                    lock["_site_blob"] = deterministic.tar_from_files(site_files, site_execs)
                    lock["_site_members"] = len(site_files)
    return lock


def _lock_still_valid(lock, reqs, rt) -> bool:
    if not isinstance(lock, dict) or lock.get("lock_version") != 1:
        return False
    meta = lock.get("runtime", {})
    if meta.get("version") != rt["version"] or meta.get("target") != rt["target"]:
        return False
    declared = {f"{p['name']}=={p['version']}" for p in lock.get("packages", [])}
    pinned = {r for r in reqs if "==" in r}
    if not pinned.issubset(declared):
        return False
    top = {p["name"] for p in lock.get("packages", [])}
    for r in reqs:
        base = r.split("=")[0].split(">")[0].split("<")[0].split("!")[0].strip().lower().replace("_", "-")
        if base and base not in top and not any(t.startswith(base) for t in top):
            return False
    return True


def pack(source_dir=".", output_path=None, *, progress=None, target=None) -> str:
    """Create a .blackbox package. Returns the output path."""
    source_dir = os.path.abspath(str(source_dir))
    manifest = load_source(source_dir)
    if target:
        from blackbox.platform import SUPPORTED_TARGETS
        if target not in SUPPORTED_TARGETS:
            raise BlackboxError(f"Unknown target '{target}'.",
                                detail="Known: " + ", ".join(sorted(SUPPORTED_TARGETS)))
        manifest["runtime"]["target"] = target
    rt = manifest["runtime"]
    provider = get_provider(rt["type"])
    say = progress or (lambda s: None)
    cas = CAS()

    say(f"resolving dependencies for {manifest['name']} ({rt['type']} {rt['version']})...")
    lock = build_lock(source_dir, manifest, provider=provider)

    app_files, app_execs = deterministic.collect_tree(
        source_dir, exclude=EXCLUDE_AT_PACK + [f"{manifest['name']}-work"])
    app_blob = deterministic.tar_from_files(app_files, app_execs)
    app_digest = "sha256:" + deterministic.sha256_bytes(app_blob)

    deps_blob, deps_execs = lock.pop("_site_blob", b""), None
    if rt["type"] == "python" and lock["packages"]:
        say(f"fetching {len(lock['packages'])} locked package(s)...")
        wheels_dir = resolver.fetch_locked(lock, cas)
        say("building dependency layer...")
        site_files = resolver.build_site_packages(lock, wheels_dir)
        deps_blob = deterministic.tar_from_files(site_files)
    members_lock = yaml.safe_dump(lock, sort_keys=True).encode("utf-8")

    layers = [
        {"kind": "application", "digest": app_digest, "file": fmt.APP_LAYER,
         "members": len(app_files), "bytes": len(app_blob), "exec": app_execs},
    ]
    if deps_blob:
        deps_digest = "sha256:" + deterministic.sha256_bytes(deps_blob)
        layers.append({"kind": "dependencies", "digest": deps_digest, "file": fmt.DEPS_LAYER,
                       "members": lock.get("_site_members"), "bytes": len(deps_blob),
                       "exec": deps_execs or []})
        lock.pop("_site_members", None)

    members = {
        fmt.MANIFEST: deterministic.canon_json(manifest),
        fmt.LOCK: members_lock,
        fmt.APP_LAYER: app_blob,
        fmt.LAYERS_INDEX: deterministic.canon_json({"layers": layers}),
    }
    if deps_blob:
        members[fmt.DEPS_LAYER] = deps_blob
    members[fmt.PROVENANCE] = deterministic.canon_json({
        "tool": f"blackbox {__version__}",
        "host": bb_platform.current_triple(),
        "target": rt["target"],
        "runtime": {"type": rt["type"], "version": rt["version"]},
        "layers": [l["digest"] for l in layers],
    })

    buf = io.BytesIO()
    ordered = [k for k in fmt.MEMBER_ORDER if k in members]
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ordered:
            deterministic.add_to_deterministic_zip(zf, name, members[name])
    checksums = {name: deterministic.sha256_bytes(members[name]) for name in ordered}
    with zipfile.ZipFile(buf, "a", zipfile.ZIP_DEFLATED) as zf:
        deterministic.add_to_deterministic_zip(zf, fmt.CHECKSUMS, deterministic.canon_json({"sha256": checksums}))

    cas.put_bytes(app_blob)
    if deps_blob:
        cas.put_bytes(deps_blob)

    out = output_path or os.path.join(source_dir, f"{manifest['name']}.blackbox")
    out = str(out)
    if os.path.isdir(out):
        out = os.path.join(out, f"{manifest['name']}.blackbox")
    with open(out, "wb") as f:
        f.write(buf.getvalue())
    say(f"wrote {out} ({deterministic.human_size(os.path.getsize(out))})")
    return out
