"""The .blackbox package format (specification: docs/format.md).

A .blackbox file is a deterministic ZIP container:

    manifest.json      canonical JSON of the normalized manifest
    blackbox.lock      YAML lockfile: exact versions, urls, sha256
    application.tar.zst  deterministic layer: source + assets (sorted, zeroed metadata)
    dependencies.tar.zst deterministic layer: installed site-packages (if any)
    layers.json        layer index: {kind, name, digest, members}
    checksums.json     sha256 of every other member (integrity root)
    signature.json     optional Ed25519 signature over the content digest

Layers are content-addressed; two packages sharing a dependency set share the
identical layer blob byte-for-byte, which is what makes deduplication and
future delta updates possible.
"""

MANIFEST = "manifest.json"
LOCK = "blackbox.lock"
APP_LAYER = "application.tar.zst"
DEPS_LAYER = "dependencies.tar.zst"
LAYERS_INDEX = "layers.json"
CHECKSUMS = "checksums.json"
SIGNATURE = "signature.json"

MEMBER_ORDER = [MANIFEST, LOCK, APP_LAYER, DEPS_LAYER, LAYERS_INDEX, CHECKSUMS, SIGNATURE]
