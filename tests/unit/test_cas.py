import os

import pytest

from blackbox.errors import IntegrityError
from blackbox.storage.cas import CAS


@pytest.fixture()
def cas(tmp_path):
    os.makedirs(tmp_path / "objects", exist_ok=True)
    return CAS(root=tmp_path / "objects")


class TestCAS:
    def test_put_get_dedup(self, cas):
        r1 = cas.put_bytes(b"hello layer")
        r2 = cas.put_bytes(b"hello layer")
        assert r1 == r2 == "sha256:" + __import__("hashlib").sha256(b"hello layer").hexdigest()
        # physically one object
        objs = [f for _, _, fs in os.walk(cas.root) for f in fs]
        assert len(objs) == 1

    def test_immutable_and_verifiable(self, cas):
        ref = cas.put_bytes(b"payload")
        assert cas.verify(ref)
        path = cas.get_path(ref)
        with open(path, "ab") as f:  # tamper
            f.write(b"x")
        assert not cas.verify(ref)
        assert ref in cas.check_all()

    def test_missing_object_clear_error(self, cas):
        with pytest.raises(IntegrityError) as e:
            cas.get_path("sha256:" + "ab" * 32)
        assert "missing" in str(e.value).lower()

    def test_malformed_ref(self, cas):
        with pytest.raises(IntegrityError):
            cas.get_path("md5:short")

    def test_put_file(self, cas, tmp_path):
        p = tmp_path / "blob.bin"
        p.write_bytes(b"file contents")
        ref = cas.put_file(p)
        assert cas.verify(ref)
        assert open(cas.get_path(ref), "rb").read() == b"file contents"

    def test_stats(self, cas):
        cas.put_bytes(b"a")
        cas.put_bytes(b"bb")
        st = cas.stats()
        assert st["objects"] == 2 and st["bytes"] == 3
