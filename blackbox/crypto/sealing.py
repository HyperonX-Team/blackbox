"""Sealed secrets: encrypt a secrets file INTO a package, decrypt only at run time.

Design (no invented cryptography):

  * `blackbox keygen <name>` creates an Ed25519 signing pair AND an X25519
    "seal" pair (`<name>.seal.pub.pem` / `<name>.seal.key.pem`) in the BLACKBOX
    home keys directory.
  * `blackbox seal <pkg> --secrets .env --to <recipient>.seal.pub.pem` generates
    a fresh ephemeral X25519 keypair, does an ECDH with the recipient, and
    AES-256-GCM encrypts the payload. The sealed blob is appended to the
    package as `secrets.json`.
  * At `blackbox run`, the runner computes the recipient fingerprint from the
    blob, looks for `~/.blackbox/keys/<fingerprint>.seal.key.pem`, decrypts and
    injects KEY=VALUE pairs as environment variables (they never touch disk).

Without the matching private seal key the payload is unreadable - shipping a
package with sealed secrets is safe even on a public link.
"""

import base64
import hashlib
import json
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from blackbox.errors import BlackboxError
from blackbox.storage import paths

SEAL_ALG = "x25519-aesgcm-256"


def _load_pub_pem(data: bytes) -> X25519PublicKey:
    try:
        key = serialization.load_pem_public_key(data)
    except (ValueError, TypeError) as e:
        raise BlackboxError("The --to file is not a valid PEM public key.", detail=str(e))
    if not isinstance(key, X25519PublicKey):
        raise BlackboxError("The --to key is not an X25519 sealing public key.",
                            detail="Seal keys are the '*.seal.pub.pem' files created by 'blackbox keygen'.")
    return key


def seal_bytes(payload: bytes, recipient_pub_pem: bytes) -> bytes:
    """Encrypt payload to a recipient; returns the JSON blob for secrets.json."""
    pub = _load_pub_pem(recipient_pub_pem)
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(pub)
    aes = AESGCM(shared)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, payload, None)
    blob = {
        "alg": SEAL_ALG,
        "recipient": recipient_pub_pem.decode("ascii"),
        "ephemeral": base64.b64encode(eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }
    return json.dumps(blob, sort_keys=True, indent=2).encode("utf-8")


def recipient_fingerprint(recipient_pub_pem: bytes) -> str:
    return hashlib.sha256(recipient_pub_pem).hexdigest()[:16]


def _private_seal_path(recipient_pub_pem: bytes):
    kd = paths.home() / "keys"
    return kd / f"{recipient_fingerprint(recipient_pub_pem)}.seal.key.pem"


def _find_private_seal_key(recipient_pub_pem: bytes):
    """Locate the private seal key matching the recipient public key.

    Checks the fingerprint-named file first, then scans the keys dir (covers
    keys copied over under their keygen name, e.g. 'lab.seal.key.pem').
    """
    kd = paths.home() / "keys"
    want = recipient_fingerprint(recipient_pub_pem)
    direct = kd / f"{want}.seal.key.pem"
    if direct.is_file():
        return direct
    if kd.is_dir():
        for p in sorted(kd.glob("*.seal.key.pem")):
            try:
                priv = serialization.load_pem_private_key(p.read_bytes(), password=None)
                if isinstance(priv, X25519PrivateKey):
                    pub_pem = priv.public_key().public_bytes(
                        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                    if hashlib.sha256(pub_pem).hexdigest()[:16] == want:
                        return p
            except (ValueError, TypeError, OSError):
                continue
    return None


def open_sealed(blob_bytes: bytes) -> dict:
    """Decrypt a secrets.json blob using the local private seal key.

    Returns {key: value}. Raises BlackboxError when the local key is missing.
    """
    try:
        blob = json.loads(blob_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise BlackboxError("Package contains a malformed sealed-secrets payload.", detail=str(e))
    if blob.get("alg") != SEAL_ALG:
        raise BlackboxError(f"Unsupported secrets algorithm '{blob.get('alg')}'.")
    recipient_pem = blob.get("recipient", "").encode("ascii")
    key_path = _find_private_seal_key(recipient_pem)
    if key_path is None:
        raise BlackboxError(
            "This package carries sealed secrets, but your machine does not hold the "
            "matching private seal key.",
            detail=f"Recipient fingerprint: {recipient_fingerprint(recipient_pem)}",
            try_hint="Ask the publisher for their '*.seal.key.pem' file and place it in "
                     f"{paths.home() / 'keys'} , then re-run.")
    try:
        priv = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(priv, X25519PrivateKey):
            raise BlackboxError(f"{key_path} is not an X25519 private seal key.")
        eph_pub = X25519PublicKey.from_public_bytes(base64.b64decode(blob["ephemeral"]))
        shared = priv.exchange(eph_pub)
        pt = AESGCM(shared).decrypt(base64.b64decode(blob["nonce"]),
                                    base64.b64decode(blob["ct"]), None)
    except BlackboxError:
        raise
    except Exception as e:
        raise BlackboxError("Sealed secrets could not be decrypted with the local key.",
                            detail=str(e))
    out = {}
    for ln in pt.decode("utf-8").splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        k, _, v = ln.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def parse_secrets_file(path) -> list:
    """Parse KEY=VALUE lines; returns [(key, value)]. Validates names."""
    import re
    name_re = __import__("blackbox.manifest.schema", fromlist=["ENV_NAME_RE"]).ENV_NAME_RE
    pairs = []
    try:
        text = open(str(path), encoding="utf-8").read()
    except OSError as e:
        raise BlackboxError(f"Could not read the secrets file: {path}", detail=str(e))
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if "=" not in ln:
            raise BlackboxError(f"Secrets line is not KEY=VALUE: '{ln[:40]}'")
        k, _, v = ln.partition("=")
        k = k.strip()
        if not name_re.match(k):
            raise BlackboxError(f"Invalid secret name '{k}'.")
        pairs.append((k, v.strip().strip('"').strip("'")))
    if not pairs:
        raise BlackboxError("The secrets file contains no KEY=VALUE entries.")
    return pairs
