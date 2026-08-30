"""Package signing and publisher trust (Ed25519 via the `cryptography` crate binding).

Signatures commit to the package's content digest: sha256 over the canonical
JSON of all member hashes. signature.json is appended as a ZIP member, so a
signed package remains a valid, openable BLACKBOX.

We do not invent cryptography: keys are standard Ed25519, stored as PEM.
Trust is a local decision: `blackbox trust <pubkey-file> --publisher NAME`
pins a public key so verify/run can display "Signature: VALID".
"""

import json
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from blackbox import deterministic
from blackbox.errors import BlackboxError
from blackbox.packaging import format as fmt
from blackbox.storage import paths

KEYS_SUBDIR = "keys"


def _keys_dir():
    d = paths.home() / KEYS_SUBDIR
    d.mkdir(parents=True, exist_ok=True)
    return d


def keygen(name: str, publisher: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    kd = _keys_dir()
    priv_path = kd / f"{name}.key.pem"
    pub_path = kd / f"{name}.pub.pem"
    if priv_path.exists():
        raise BlackboxError(f"A key named '{name}' already exists.",
                            detail=str(priv_path))
    priv = Ed25519PrivateKey.generate()
    priv_path.write_bytes(priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    pub_path.write_bytes(priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    # sealing pair (X25519) used by 'blackbox seal' — separate from signing on purpose
    seal_priv = X25519PrivateKey.generate()
    seal_key_path = kd / f"{name}.seal.key.pem"
    seal_pub_path = kd / f"{name}.seal.pub.pem"
    seal_key_path.write_bytes(seal_priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    seal_pub_path.write_bytes(seal_priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    if os.name != "nt":
        for p in (priv_path, seal_key_path):
            os.chmod(p, 0o600)
    meta = {"name": name, "publisher": publisher, "created": "deterministic-clock-avoided"}
    (kd / f"{name}.meta.json").write_text(json.dumps(meta, sort_keys=True))
    return {"private": str(priv_path), "public": str(pub_path),
            "seal_private": str(seal_key_path), "seal_public": str(seal_pub_path),
            "publisher": publisher}


def _pub_pem_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def sign_package(package, *, key_name=None, private_key=None, publisher=None) -> bytes:
    """Return signature.json payload for an opened Package."""
    if private_key is None:
        if not key_name:
            raise BlackboxError("No signing key specified.",
                                try_hint="blackbox keygen <name>   then   blackbox sign pkg --key <name>")
        kd = _keys_dir()
        pem = (kd / f"{key_name}.key.pem").read_bytes()
        private_key = serialization.load_pem_private_key(pem, password=None)
        if publisher is None:
            meta_file = kd / f"{key_name}.meta.json"
            if meta_file.exists():
                publisher = json.loads(meta_file.read_text()).get("publisher", key_name)
    signature = private_key.sign(package.content_digest.encode("utf-8"))
    return deterministic.canon_json({
        "alg": "ed25519",
        "publisher": publisher or "anonymous",
        "public_key": _pub_pem_bytes(private_key.public_key()).decode("ascii"),
        "signature": signature.hex(),
        "content_digest": package.content_digest,
    })


def attach_signature(pkg_path, signature_json: bytes):
    """Append signature.json to the ZIP member list in place (deterministic order preserved)."""
    import io
    import zipfile

    with zipfile.ZipFile(str(pkg_path)) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    members[fmt.SIGNATURE] = signature_json
    buf = io.BytesIO()
    ordered = [k for k in fmt.MEMBER_ORDER if k in members] + sorted(set(members) - set(fmt.MEMBER_ORDER))
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in ordered:
            deterministic.add_to_deterministic_zip(zf, name, members[name])
    with open(str(pkg_path), "wb") as f:
        f.write(buf.getvalue())


def verify_package(package) -> dict:
    """Verify signature (if present). Returns {state, publisher, digest}."""
    if fmt.SIGNATURE not in package.members:
        return {"state": "unsigned", "publisher": None, "digest": package.content_digest}
    sig = json.loads(package.members[fmt.SIGNATURE])
    if sig.get("content_digest") != package.content_digest:
        return {"state": "invalid", "publisher": sig.get("publisher"), "digest": package.content_digest,
                "reason": "signature does not match package contents"}
    try:
        pub = serialization.load_pem_public_key(sig["public_key"].encode("ascii"))
        pub.verify(bytes.fromhex(sig["signature"]), package.content_digest.encode("utf-8"))
    except (InvalidSignature, ValueError, KeyError) as e:
        return {"state": "invalid", "publisher": sig.get("publisher"), "digest": package.content_digest,
                "reason": str(e) or "bad signature encoding"}
    trusted = load_trust()
    publisher = sig.get("publisher", "?")
    pinned = trusted.get(publisher)
    key_fp = deterministic.sha256_bytes(_pub_fp_bytes(pub))
    if pinned and pinned.get("sha256") == key_fp:
        state = "trusted"
    else:
        state = "valid"
    return {"state": state, "publisher": publisher, "key_fingerprint": key_fp, "digest": package.content_digest}


def _pub_fp_bytes(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def trust_key(pub_path, publisher: str) -> dict:
    pub = serialization.load_pem_public_key(open(str(pub_path), "rb").read())
    entry = {"publisher": publisher, "sha256": deterministic.sha256_bytes(_pub_fp_bytes(pub))}
    t = load_trust()
    t[publisher] = entry
    (paths.home() / "keys" / "trusted.json").write_text(json.dumps(t, sort_keys=True, indent=2))
    return entry


def load_trust() -> dict:
    p = paths.home() / "keys" / "trusted.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return {}
