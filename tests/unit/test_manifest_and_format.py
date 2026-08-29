import json

import pytest

from blackbox import deterministic
from blackbox.errors import IntegrityError, ManifestError
from blackbox.manifest import load_manifest
from blackbox.platform import current_triple, pip_target_flags, SUPPORTED_TARGETS


def minimal(**over):
    base = {
        "format_version": "1",
        "name": "x",
        "version": "0.1.0",
        "runtime": {"type": "python", "version": "3.12"},
        "entrypoint": {"command": "python", "args": ["a.py"]},
    }
    base.update(over)
    return base


def dump(d):
    import yaml
    return yaml.safe_dump(d)


class TestManifest:
    def test_valid_minimal(self):
        m = load_manifest(dump(minimal()))
        assert m["name"] == "x"
        assert m["permissions"]["network"]["enabled"] is False  # network denied by default
        assert m["permissions"]["process"]["spawn"] is False
        assert m["runtime"]["type"] == "python"

    def test_missing_fields(self):
        with pytest.raises(ManifestError):
            load_manifest(dump({"name": "x"}))

    def test_bad_format_version(self):
        with pytest.raises(ManifestError):
            load_manifest(dump(minimal(format_version="99")))

    def test_unknown_runtime(self):
        with pytest.raises(ManifestError):
            load_manifest(dump(minimal(runtime={"type": "brainfuck", "version": "1"})))

    def test_unsupported_python(self):
        with pytest.raises(ManifestError):
            load_manifest(dump(minimal(runtime={"type": "python", "version": "2.7"})))

    def test_node_runtime_ok(self):
        m = load_manifest(dump(minimal(runtime={"type": "node", "version": "22"},
                                      entrypoint={"command": "node", "args": ["i.js"]})))
        assert m["runtime"]["type"] == "node"

    def test_native_requires_bundled_exe(self):
        with pytest.raises(ManifestError):
            load_manifest(dump(minimal(runtime={"type": "native"},
                                       entrypoint={"command": "python", "args": []})))
        m = load_manifest(dump(minimal(runtime={"type": "native"},
                                       entrypoint={"command": "./bin/app", "args": []})))
        assert m["runtime"]["version"] == "any"

    def test_absolute_path_permission_rejected(self):
        with pytest.raises(ManifestError):
            load_manifest(dump(minimal(permissions={"filesystem": {"write": ["/etc/passwd"]}})))

    def test_traversal_permission_rejected(self):
        with pytest.raises(ManifestError):
            load_manifest(dump(minimal(permissions={"filesystem": {"write": ["./../escape"]}})))

    def test_entrypoint_command_mismatch(self):
        with pytest.raises(ManifestError):
            load_manifest(dump(minimal(runtime={"type": "node", "version": "22"},
                                       entrypoint={"command": "python", "args": []})))

    def test_invalid_yaml(self):
        with pytest.raises(ManifestError):
            load_manifest("name: [unclosed")


class TestDeterminism:
    def test_tar_roundtrip_and_stability(self):
        files = {"b.txt": b"two", "a.txt": b"one", "dir/": None}
        t1 = deterministic.tar_from_files(files, exec_paths=["b.txt"])
        t2 = deterministic.tar_from_files(dict(sorted(reversed(list(files.items())))))
        back = deterministic.files_from_tar(t1)
        assert back["a.txt"] == b"one" and back["b.txt"] == b"two"
        assert "dir/" in back
        # insertion order must not matter except exec bits normalize modes;
        # with same exec set output must be byte-identical
        assert t1 == deterministic.tar_from_files(files, exec_paths=["b.txt"])

    def test_zip_member_is_deterministic(self):
        import io
        import zipfile
        blobs = []
        for _ in range(2):
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                deterministic.add_to_deterministic_zip(zf, "m.json", b'{"a":1}')
            blobs.append(buf.getvalue())
        assert blobs[0] == blobs[1]

    def test_canon_json_stable(self):
        assert deterministic.canon_json({"b": 1, "a": [2, {"d": 4, "c": 3}]}) == \
            deterministic.canon_json({"a": [2, {"c": 3, "d": 4}], "b": 1})

    def test_collect_tree_skips_junk(self, tmp_path):
        (tmp_path / "keep.txt").write_bytes(b"k")
        (tmp_path / "junk.pyc").write_bytes(b"j")
        (tmp_path / "old.blackbox").write_bytes(b"z")
        (tmp_path / "__pycache__").mkdir()
        (tmp_path / "__pycache__" / "m.pyc").write_bytes(b"p")
        files, _ = deterministic.collect_tree(tmp_path)
        assert set(files) == {"keep.txt"}

    def test_extract_rejects_path_escape(self, tmp_path):
        with pytest.raises(Exception):
            deterministic.extract_tree({"../evil": b"x"}, tmp_path / "out")


class TestPlatform:
    def test_current_triple_supported(self):
        assert current_triple() in SUPPORTED_TARGETS

    def test_pip_flags_carry_target_version(self):
        flags = pip_target_flags("x86_64-unknown-linux-gnu", "3.12")
        joined = " ".join(flags)
        assert "--python-version 312" in joined and "manylinux" in joined


class TestSigningUnit:
    def test_keygen_creates_pairs(self, isolated_home):
        from blackbox.crypto import signing
        r = signing.keygen("t1", "Publisher A")
        import os
        assert os.path.isfile(r["private"]) and os.path.isfile(r["public"])
