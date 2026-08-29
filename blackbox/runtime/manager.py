"""Runtime management entry points retained for CLI compatibility.

Provisioning logic now lives in blackbox.runtime.providers; this module keeps
the offline seeding (`blackbox runtime import <python-build-standalone tarball>`)
and a facade for doctor/listing.
"""

import os
import shutil

from blackbox import platform as bb_platform
from blackbox.deterministic import sha256_file
from blackbox.errors import RuntimeMissingError
from blackbox.runtime.providers import PythonProvider
from blackbox.storage import paths


class RuntimeManager(PythonProvider):
    def __init__(self, cas=None):
        pass

    def runtime_dir(self, python_version, target):
        return self._dir(python_version, target)

    def python_exe(self, python_version, target):
        return self.executable(python_version, target)

    def import_tarball(self, path) -> dict:
        base = os.path.basename(str(path))
        if not base.startswith("cpython-") or not base.endswith(".tar.gz"):
            raise RuntimeMissingError(f"'{base}' is not a python-build-standalone install_only tarball.")
        stem = base[len("cpython-"):-len(".tar.gz")]
        full, rest = stem.split("+", 1)
        tag = rest.split("-")[0]
        triple = rest[len(tag) + 1:].removesuffix("-install_only")
        family = ".".join(full.split(".")[:2])
        if triple not in bb_platform.SUPPORTED_TARGETS or family not in self.PINNED:
            raise RuntimeMissingError(f"Unsupported runtime build: {base}")
        sidecar = str(path) + ".sha256"
        actual = sha256_file(path)
        if os.path.isfile(sidecar):
            with open(sidecar) as f:
                expected = f.read().split()[0]
            if expected != actual:
                raise RuntimeMissingError("Tarball does not match its .sha256 sidecar; refusing to install.")
        with open(path, "rb") as f:
            self._extract(f.read(), self._dir(family, triple))
        return {"family": family, "full": full, "target": triple, "sha256": actual}

    def installed(self):
        from blackbox.runtime.providers import PROVIDERS
        triple = bb_platform.current_triple()
        res = []
        for fam in sorted(PythonProvider.PINNED):
            res.append(("python", fam, self.is_installed(fam, triple)))
        from blackbox.runtime.providers import NodeProvider
        for fam in sorted(NodeProvider.SUPPORTED_MAJORS):
            res.append(("node", fam, NodeProvider().is_installed(fam, triple)))
        return res


def _nonempty(p) -> bool:
    return any(p.iterdir()) if p.is_dir() else False
