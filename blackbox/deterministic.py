"""Deterministic primitives: hashing, canonical JSON, reproducible tar/zip.

Same inputs -> same bytes is a product requirement (see docs/format.md).
Everything here avoids timestamps, OS metadata, and dictionary ordering.
"""

import hashlib
import io
import json
import os
import tarfile
import zipfile

from blackbox.errors import PackageFormatError

import zstandard as zstd

# Fixed epoch for all archive members: 1980-01-01 (ZIP minimum).
FIXED_MTIME = 315532800
FIXED_ZIP_DATE = (1980, 1, 1, 0, 0, 0)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_stream(fileobj) -> str:
    h = hashlib.sha256()
    for chunk in iter(lambda: fileobj.read(1 << 20), b""):
        h.update(chunk)
    return h.hexdigest()


def canon_json(obj) -> bytes:
    """Canonical JSON: sorted keys, tight separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def zstd_compress(data: bytes) -> bytes:
    return zstd.ZstdCompressor(level=3).compress(data)


def zstd_decompress(data: bytes) -> bytes:
    return zstd.ZstdDecompressor().decompressobj(64 * 10**6).decompress(data)


def _norm_mode(mode: int, is_dir: bool, is_exec: bool) -> int:
    if is_dir:
        return 0o755
    return 0o755 if is_exec else 0o644


def tar_from_files(files: dict, exec_paths=()) -> bytes:
    """Deterministic zstd-compressed tar from {arcname: bytes} (plus 'dir/' keys -> b'')."""
    exec_set = set(exec_paths)
    buf = io.BytesIO()
    cctx = zstd.ZstdCompressor(level=3)
    with cctx.stream_writer(buf, closefd=False) as comp, tarfile.open(fileobj=comp, mode="w|") as tar:
        for name in sorted(files):
            info = tarfile.TarInfo(name.rstrip("/"))
            data = files[name]
            info.mtime = FIXED_MTIME
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            if name.endswith("/") or data is None:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
            else:
                info.type = tarfile.REGTYPE
                info.mode = _norm_mode(0, False, name in exec_set)
                payload = bytes(data)
                info.size = len(payload)
            tar.addfile(info, io.BytesIO(b"" if info.isdir() else payload))
    return buf.getvalue()


def files_from_tar(blob: bytes) -> dict:
    """Inverse of tar_from_files: {arcname: bytes} (dirs as None)."""
    out = {}
    dctx = zstd.ZstdDecompressor()
    with dctx.stream_reader(io.BytesIO(blob)) as dec, tarfile.open(fileobj=dec, mode="r|") as tar:
        while True:
            m = tar.next()
            if m is None:
                break
            if m.isdir():
                out[m.name.rstrip("/") + "/"] = None
            elif m.isfile():
                f = tar.extractfile(m)
                out[m.name] = f.read()
    return out


def add_to_deterministic_zip(zf: zipfile.ZipFile, name: str, data: bytes):
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_DATE)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    info.create_system = 3
    info.extra = b""
    info.comment = b""
    zf.writestr(info, data)


def collect_tree(root, *, exclude=()) -> tuple:
    """Collect ({relpath: bytes}, sorted exec paths) under root, skipping junk/excluded."""
    files = {}
    execs = []
    root = os.path.abspath(str(root))
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        skip = False
        for exc in exclude:
            e = exc.rstrip("/")
            if rel_dir == e or rel_dir.startswith(e + "/"):
                skip = True
                break
        if skip:
            dirnames[:] = []
            continue
        dirnames[:] = [d for d in dirnames if not _is_junk(d)]
        for fn in sorted(filenames):
            if _is_junk(fn):
                continue
            rel = f"{rel_dir}/{fn}" if rel_dir else fn
            if any(rel == e.rstrip("/") or rel.startswith(e.rstrip("/") + "/") for e in exclude):
                continue
            full = os.path.join(dirpath, fn)
            files[rel] = open(full, "rb").read()
            if os.name != "nt" and os.access(full, os.X_OK):
                execs.append(rel)
    return files, sorted(execs)


def _is_junk(name: str) -> bool:
    return (name in ("__pycache__", ".DS_Store") or name.endswith((".pyc", ".pyo", ".blackbox"))
            or name.startswith(".blackbox-tmp") or name.endswith(".staging"))


def extract_tree(files: dict, dest_root, *, overwrite=False, execs=()):
    import pathlib

    exec_set = set(execs)
    dest_root = pathlib.Path(dest_root)
    staged = dest_root.parent / (dest_root.name + ".blackbox-tmp")
    if staged.exists():
        _rmtree(staged)
    staged.mkdir(parents=True)
    for name, data in files.items():
        target = (staged / name).resolve()
        if not str(target).startswith(str(staged.resolve())):
            raise PackageFormatError(f"Refusing unsafe path in package: {name}")
        if name.endswith("/"):
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
        if os.name != "nt" and name in exec_set:
            os.chmod(target, 0o755)
    if dest_root.exists():
        if not overwrite:
            _rmtree(staged)
            return False
        _rmtree(dest_root)
    staged.rename(dest_root)
    return True


def _rmtree(path):
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
