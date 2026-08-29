"""Content-addressed object store.

Objects are immutable and addressed by sha256 digest: objects/sha256/<aa>/<full-hash>.
Deduplication is the whole point: identical layers (runtimes, dependency bundles,
application trees) are stored exactly once regardless of how many packages use them.
"""

import json
import os
import shutil
import tempfile

from blackbox import deterministic
from blackbox.errors import IntegrityError
from blackbox.storage import paths


class CAS:
    def __init__(self, root=None):
        self.root = os.path.abspath(str(root or paths.home() / "objects"))

    def _path(self, digest_hex: str) -> str:
        return os.path.join(self.root, "sha256", digest_hex[:2], digest_hex)

    def has(self, digest_hex: str) -> bool:
        return os.path.isfile(self._path(digest_hex))

    def put_bytes(self, data: bytes) -> str:
        digest = deterministic.sha256_bytes(data)
        dest = self._path(digest)
        if os.path.isfile(dest):
            return "sha256:" + digest
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.root)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, dest)
        except OSError:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return "sha256:" + digest

    def put_file(self, src_path) -> str:
        digest = deterministic.sha256_file(src_path)
        dest = self._path(digest)
        if os.path.isfile(dest):
            return "sha256:" + digest
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copyfile(str(src_path), dest)
        return "sha256:" + digest

    def get_path(self, ref: str) -> str:
        digest_hex = self._parse(ref)
        p = self._path(digest_hex)
        if not os.path.isfile(p):
            raise IntegrityError(
                f"Cached object is missing from the local store.",
                detail=f"Requested: {ref}\nAttempted: {p}",
                try_hint="blackbox cache --clear  (then re-run; the object will be rebuilt or re-fetched)",
            )
        return p

    def verify(self, ref: str) -> bool:
        p = self.get_path(ref)
        return "sha256:" + deterministic.sha256_file(p) == ref

    def delete(self, ref: str):
        digest_hex = self._parse(ref)
        p = self._path(digest_hex)
        if os.path.isfile(p):
            os.unlink(p)

    def _parse(self, ref: str) -> str:
        if not ref.startswith("sha256:") or len(ref) != 71:
            raise IntegrityError(f"Malformed object reference: {ref!r}")
        return ref[7:]

    def stats(self) -> dict:
        total_objs = 0
        total_bytes = 0
        base = os.path.join(self.root, "sha256")
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                total_objs += 1
                total_bytes += os.path.getsize(os.path.join(dirpath, fn))
        return {"objects": total_objs, "bytes": total_bytes, "root": self.root}

    def clear(self):
        base = os.path.join(self.root, "sha256")
        shutil.rmtree(base, ignore_errors=True)
        os.makedirs(base, exist_ok=True)

    def check_all(self):
        """Verify every stored object's digest; return list of corrupt refs."""
        corrupt = []
        base = os.path.join(self.root, "sha256")
        for dirpath, _dirs, files in os.walk(base):
            for fn in files:
                full = os.path.join(dirpath, fn)
                actual = deterministic.sha256_file(full)
                if actual != fn:
                    corrupt.append("sha256:" + fn)
        return sorted(corrupt)
