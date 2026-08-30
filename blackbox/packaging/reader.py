"""blackbox run/inspect/verify/unpack: reading and installing .blackbox packages."""

import io
import json
import os
import zipfile
import zlib

import yaml

from blackbox import deterministic
from blackbox.errors import IntegrityError, PackageFormatError
from blackbox.manifest import load_manifest
from blackbox.packaging import format as fmt
from blackbox.runtime.providers import get_provider
from blackbox.runtime.runner import RunContext
from blackbox.storage import paths
from blackbox.storage.cas import CAS

CONTENT_MEMBERS = [fmt.MANIFEST, fmt.LOCK, fmt.APP_LAYER, fmt.DEPS_LAYER, fmt.LAYERS_INDEX]


class Package:
    def __init__(self, path, members: dict, manifest: dict, checksums: dict):
        self.path = str(path)
        self.members = members
        self.manifest = manifest
        self.checksums = checksums

    @property
    def content_digest(self) -> str:
        """Digest over content members; the thing signatures commit to."""
        canon = deterministic.canon_json({k: self.checksums[k] for k in self.checksums if k != fmt.SIGNATURE})
        return "sha256:" + deterministic.sha256_bytes(canon)

    def package_id(self) -> str:
        return f"{self.manifest['name']}-{self.manifest['version']}-{self.content_digest[7:19]}"


def open_package(path, *, verify=True) -> Package:
    path = str(path)
    if not os.path.isfile(path):
        raise PackageFormatError(f"No such BLACKBOX file: {path}")
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            members = {n: zf.read(n) for n in names}
    except (zipfile.BadZipFile, zlib.error, EOFError, OSError):
        raise PackageFormatError(
            f"'{os.path.basename(path)}' is not a readable BLACKBOX package.",
            detail="The file is truncated or not in the .blackbox format.",
            try_hint="Re-copy the original file. .blackbox packages are self-contained; a partial transfer corrupts them.",
        )
    for required in (fmt.MANIFEST, fmt.LOCK, fmt.APP_LAYER, fmt.CHECKSUMS):
        if required not in members:
            raise PackageFormatError(
                f"Package is missing required member '{required}'.",
                detail=f"Members present: {', '.join(sorted(members))}",
                try_hint="This package is malformed or built by an incompatible tool. Re-pack from source.",
            )
    checksums = json.loads(members[fmt.CHECKSUMS])["sha256"]
    if verify:
        for name, want in checksums.items():
            if name not in members:
                raise IntegrityError(
                    f"Package integrity check failed: member '{name}' is missing.",
                    try_hint="The package is corrupted. Obtain a fresh copy or re-pack from source.",
                )
            got = deterministic.sha256_bytes(members[name])
            if got != want:
                raise IntegrityError(
                    f"Package integrity check failed: '{name}' does not match its recorded hash.",
                    detail=f"expected {want}\nactual   {got}",
                    try_hint="The package was modified after it was built. Re-pack or obtain a fresh copy.",
                )
    try:
        manifest = load_manifest(members[fmt.MANIFEST].decode("utf-8"))
    except Exception as e:
        from blackbox.errors import BlackboxError
        if not isinstance(e, BlackboxError):
            raise PackageFormatError("Package manifest is not a valid BLACKBOX manifest.", detail=str(e))
        raise
    return Package(path, members, manifest, checksums)


def install(pkg: Package, *, cas=None, quiet=False) -> dict:
    """Materialize layers into the local cache (deduplicated by digest).

    Returns {"app_dir": ..., "site_dir": ..., "runtime": ...}.
    """
    cas = cas or CAS()
    layers = json.loads(pkg.members[fmt.LAYERS_INDEX])["layers"]
    kind_key = {"application": "application_dir", "dependencies": "site_dir"}
    dirs = {}
    for layer in layers:
        digest = layer["digest"]
        blob = pkg.members[layer["file"]]
        if deterministic.sha256_bytes(blob) != digest[7:]:
            raise IntegrityError(
                f"Layer digest mismatch for '{layer['kind']}' layer.",
                try_hint="Re-pack the package.",
            )
        dest = paths.home() / "layers" / digest.replace(":", "_") / layer["kind"]
        if not dest.exists():
            if not quiet:
                print(f"BLACKBOX: caching {layer['kind']} layer {digest[:18]}...")
            files = deterministic.files_from_tar(blob)
            deterministic.extract_tree(files, dest, overwrite=True, execs=layer.get("exec", []))
        dirs[kind_key[layer["kind"]]] = str(dest)
    dirs.setdefault("site_dir", None)
    return dirs


def prepare_run(pkg: Package, work_dir, *, data_dir=None) -> RunContext:
    m = pkg.manifest
    rt = m["runtime"]
    provider = get_provider(rt["type"])
    import yaml
    lock = yaml.safe_load(pkg.members[fmt.LOCK].decode("utf-8")) or {}
    pin = None
    if rt["type"] == "node":
        rmeta = lock.get("runtime", {})
        pin = {k: rmeta[k] for k in ("version", "asset", "url", "sha256") if k in rmeta} or None
    runtime_exe = provider.ensure(rt["version"], rt["target"], pin=pin)
    dirs = install(pkg)
    ctx = RunContext(
        m,
        app_dir=dirs["application_dir"],
        site_dir=dirs["site_dir"] or "",
        runtime_exe=runtime_exe,
        work_dir=str(work_dir),
        triple=rt["target"],
    )
    if data_dir:
        ctx.data_dir = str(data_dir)
    if fmt.SECRETS in pkg.members:
        from blackbox.crypto import sealing
        try:
            ctx.secrets = sealing.open_sealed(pkg.members[fmt.SECRETS])
        except Exception as e:   # BlackboxError or crypto failure: run without secrets
            ctx.secrets = None
            ctx.sealed_error = str(e).splitlines()[0]
    return ctx


def unpack_all(pkg: Package, dest):
    """Full unpack for human inspection: manifest, lock, and expanded layers."""
    import pathlib

    dest = pathlib.Path(str(dest))
    dest.mkdir(parents=True, exist_ok=True)
    (dest / fmt.MANIFEST).write_bytes(pkg.members[fmt.MANIFEST])
    (dest / fmt.LOCK).write_bytes(pkg.members[fmt.LOCK])
    (dest / fmt.CHECKSUMS).write_bytes(pkg.members[fmt.CHECKSUMS])
    if fmt.SIGNATURE in pkg.members:
        (dest / fmt.SIGNATURE).write_bytes(pkg.members[fmt.SIGNATURE])
    layers = json.loads(pkg.members[fmt.LAYERS_INDEX])["layers"]
    for layer in layers:
        out = dest / layer["kind"]
        deterministic.extract_tree(deterministic.files_from_tar(pkg.members[layer["file"]]), out,
                                   overwrite=True, execs=layer.get("exec", []))
    return dest
