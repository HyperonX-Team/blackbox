# BLACKBOX Architecture

Status: MVP (format_version 1). This document describes what is *implemented*
and marks future interfaces explicitly. The package format is specified
separately in [format.md](format.md); the isolation model in [security.md](security.md).

## 1. The thesis

> A `.blackbox` file is a portable object: a program plus its runtime,
> dependencies, interface, permissions and data contract, reproducible by
> hash, runnable with no host setup.

Design constraints, in priority order (from the product brief):

1. Working end-to-end flow over architectural purity.
2. The recipient runs one command. Everything else is our problem.
3. Boring, proven technologies: ZIP, zstd, tar, SHA-256, Ed25519, YAML/JSON,
   official upstream interpreter builds, pip/npm themselves.
4. No cloud, no account, no registry in the core loop.

Language choice for the CLI: Python (the brief's own quickstart is
`pip install blackbox`). The *CLI* needs Python 3.9+; *packages* never use the
host interpreter. A future self-hosting bootstrap (`blackbox` as a native
binary BLACKBOX) is on the roadmap; the internal boundaries below already
allow it because nothing outside `blackbox/` imports anything inside it.

## 2. Package lifecycle

```
 CREATOR MACHINE                       TRANSFER               RECIPIENT MACHINE
--------------                         ---------              -----------------
 source/                                datasift.blackbox     1. open zip, verify checksums.json
   blackbox.yaml                          (one file:           2. verify signature.json (if present)
   requirements.txt / package.json        USB/email/http/       3. show consent card, user approves
   src/                                   torrent/LAN)          4. ensure runtime (cache or fetch+pin-verify)
        |                                                  .    5. materialize layers from CAS (or extract)
        v                                                             6. build policy, scrub env, jail, exec
   blackbox pack  --------> .blackbox  ------------------->         7. app reads input/, writes output/
```

`blackbox pack` is the only network-touching step (resolving dependencies);
`blackbox run` needs network only if a runtime interpreter has never been
provisioned on that machine, and never if it has.

## 3. Components

```
blackbox/
  cli/            argparse surface + human error rendering (BLACKBOX ERROR / Try: / changes)
  manifest/       blackbox.yaml parsing + strict validation -> normalized manifest dict
  packaging/      format.py (member layout) · builder.py (pack) · reader.py (open/install/unpack)
  dependency/     lock resolution (pip report / npm), hash-verified fetch, site-packages layer
  runtime/        providers.py (python | node | native) · manager.py (offline seeding)
                  runner.py (env assembly, policy, execution, web-URL surfacing)
  sandbox/        policy.py (manifest -> JSON policy) · jail.py (bwrap / sandbox-exec)
                  shim/sitecustomize.py (in-process guard for Python apps)
  storage/        paths.py (~/.blackbox layout) · cas.py (content-addressed objects)
  crypto/         signing.py (Ed25519 keygen/sign/verify/trust)
  deterministic.py canon JSON, fixed-metadata tar+zip, safe extract
  platform.py     target triples, pip cross-resolution flags
```

Rule of the house: **each layer consumes only what the layer below exposes**
(CAS ← runtime/packaging ← CLI). The store does not know what a package is;
the builder does not know what a sandbox is. Replaceability over cleverness.

## 4. Runtime providers (the multi-language extension point)

A provider implements five methods:

```python
supports(version) -> bool
pin_for_lock(version, target) -> dict      # exact interpreter identity, into blackbox.lock
ensure(version, target, pin) -> exe_path   # provision into ~/.blackbox/runtimes, verify hash
env(exe, site_dir, app_dir, target) -> dict # PYTHONPATH / NODE_PATH / ...
resolve_command(cmd, args, exe, app_dir) -> argv
```

Implemented MVP providers:

| type | interpreter source | integrity | dependencies |
|---|---|---|---|
| `python` | python-build-standalone, pinned release per 3.11/3.12/3.13 | upstream `.sha256` sidecar, verified before extract | pip resolution (`pip install --dry-run --report`) → wheels CAS → installed layer |
| `node` | official nodejs.org distributions (LTS majors 18/20/22/24) | exact version+sha256 resolved at pack time, recorded in lock, verified at run | `npm install` into isolated dir → `node_modules` layer |
| `native` | none — the package *is* the binary | binaries live inside the content-addressed app layer | none at package level (link statically) |

Cross-compiling note: Python/Node BLACKBOXes lock and build **for the
package's declared target platform** (default = build host), so a Linux
appliance can be built on Windows. A `native` package is inherently
platform-specific: one `.blackbox` per target; the manifest's `runtime.target`
makes any mismatch a clear refusal, not a segfault.

Adding Rust (cargo), R (rig/rjit), Julia (juliaup tarballs), or WASM (bundled
wasmtime + `.wasm` entry) means adding one provider class + a schema entry —
format, storage, sandbox, signing, and CLI are untouched. WASM in particular
is attractive because it *is* a sandbox the OS doesn't have to provide.

## 5. Storage: content-addressed, deduplicated

```
~/.blackbox/
  objects/sha256/<aa>/<hex>      immutable blobs: layer tars, wheel files
  runtimes/<type>/<ver>/<triple> provisioned interpreters (shared)
  layers/sha256_<hex>/<kind>     expanded layer trees (app / dependencies)
  packages/  sandbox-shim/  keys/  tmp/  logs/
```

* A *layer* is a deterministic zstd tar; its digest is its name. Two packages
  that resolve `six==1.16.0` produce byte-identical dependency layers → one
  object, one expanded tree, zero extra copies.
* Wheels themselves are CAS objects keyed by their lockfile sha256 → repeated
  packs never re-download; a corrupted cache object is detected by re-hashing
  and self-heals by re-fetch.
* Layer *content* is machine-verified on first expansion (digest check before
  extraction) and on demand via `blackbox cache --check`.
* This is the seam where future remote sources live: `CAS.get(ref)` can gain a
  fetcher (`file://`, `http://`, LAN, p2p) without touching packages — see
  roadmap.

### Determinism (how "same in ⇒ same out" is achieved)

* Manifests are serialized as canonical JSON (sorted keys, no floats).
* Locks are YAML with `sort_keys`.
* Layer tars: members sorted, mtime fixed to 1980-01-01, uid/gid/uname zeroed,
  modes normalized to 0644/0755; the only semantic metadata retained is the
  exec bit. pip's build-path-dependent `RECORD`/`direct_url.json` files are
  stripped (they contain no runtime-needed data).
* The outer ZIP: fixed member order, fixed timestamps/attrs, no comments.
* Result verified by test: packing the same source twice yields byte-identical
  `.blackbox` files (`test_pack_is_deterministic`).

## 6. Build process (`pack`)

1. Load + strictly validate `blackbox.yaml` (unknown runtime, absolute
   permission paths, traversal paths → hard error).
2. Resolve deps for `runtime.target` (empty requirements ⇒ no network):
   pip report or npm; record exact versions/URLs/hashes → `blackbox.lock`
   (also written into the source dir for VCS).
3. Build the dependency layer: hash-verified wheel fetch → `pip install
   --target` into a throwaway dir → collect tree → deterministic tar.
4. Application layer: source tree minus lockfile/outputs/`*.blackbox`.
5. Emit ZIP + `layers.json` index + `checksums.json`; store layers in CAS.
6. Optional: `blackbox sign` appends `signature.json`.

## 7. Run process (`run`)

1. `open_package`: ZIP readable → every member hash-checked → manifest revalidated.
2. Signature state computed; INVALID ⇒ refuse. Unsigned ⇒ consent card
   (permissions summary + [y/N], remembered per content digest).
3. `provider.ensure(...)` interpreter: cache hit ⇒ zero network; miss ⇒ pinned
   download + hash verify + safe extract (traversal-checked) + atomic rename.
4. Layer install: if `layers/<digest>` absent, expand from the package blob.
5. `build_launch`: scrubbed env (interpreter PATH only, HOME/TMP redirected
   into the work dir, no host site-packages, `BLACKBOX_INPUT/OUTPUT/WORK` set,
   manifest env vars applied), policy JSON for the shim, platform jail
   wrapper (bwrap / sandbox-exec) where available.
6. Exec; stream output (surfacing `http://127.0.0.1:<port>` for web
   interfaces); propagate exit code. `input/` and `output/` under the work
   dir are the *only* host-visible surfaces by default.

## 8. Security model (summary — see security.md)

Manifest-declared, default-deny permissions: `filesystem.read/write`
(relative `./` paths only), `network.enabled` (false), `process.spawn`
(false). Enforcement tiers: platform jail (Linux bwrap with netns; macOS
sandbox-exec) + in-process shim (Python) + consent-before-first-run +
cryptographic integrity (checksums, Ed25519 signatures, runtime hash pins).
BLACKBOX sandboxing is an isolation boundary, not a formally verified
security boundary.

## 9. Trust

* Integrity (checksums) answers "did the file arrive uncorrupted?"
* Signing (Ed25519 over the content digest) answers "who built this, and did
  it change since?" — `keygen`, `sign`, `trust <pubkey>`, and verify/run
  display `VALID / trusted publisher / INVALID`.
* Trust is deliberately local and explicit (a keyring file), not a web of
  trust and not a central CA. X.509 or sigstore-style transparency logs can
  be layered on later without changing the format's slot.

## 10. Future: distribution & composition

* **Sources**: objects are fetched by digest already; an `object source`
  interface (`local → http → lan → p2p`) drops under `CAS.get` unchanged.
  Packages can then ship as *manifest + layer references only* ("thin
  packages") for instant download, at the cost of the "one portable file"
  guarantee — which is why the MVP keeps everything embedded.
* **Delta update**: layer digests give it for free — diff two packages'
  `layers.json`, transfer the set difference.
* **Composition**: `composite` packages will reference component `.blackbox`
  digests and wire `output/ → input/` between stages (data-cleaner →
  simulation → visualizer). The filesystem contract already matches this
  model.
* **Desktop launcher**: `interface.type` is read by the CLI today (web apps
  surface their URL); a GUI that double-clicks `.blackbox` files and renders
  the same consent card is a UI over identical primitives.

## 11. Justified deviations from the original brief

* Package is ZIP-of-tars rather than the illustrative
  `runtime/ dependencies/` directories: runtimes are 25-60 MB each and
  universal; embedding them per-package would break the size/dedup goals.
  The lockfile + pinned providers preserve the *behavior* (recipient needs
  nothing) while keeping the file small. The in-package layout in
  format.md is the authoritative spec.
* `blackbox.yaml` is the authoring surface; `manifest.json` (canonical) is
  the wire format. Both documented.
* Lockfile schema nests `packages` (list of name/version/url/sha256) rather
  than a mapping — same guarantees, simpler diffing.
