# Cache & deduplication

Everything BLACKBOX stores lives under one directory you own:

```
~/.blackbox/            (override with the BLACKBOX_HOME env var)
├── objects/sha256/<aa>/<hex>   content-addressed store (immutable blobs)
├── runtimes/<type>/<ver>/<triple>/   provisioned interpreters (shared)
├── layers/sha256_<digest>/<kind>/    expanded layer trees
├── keys/               signing keys + trust store
├── sandbox-shim/       the in-process guard injected into Python apps
├── tmp/  logs/  approvals.json
```

## Content addressing

A blob's name *is* its SHA-256. Identical inputs ⇒ identical name ⇒ stored
once. Consequences:

- **Two packages, same `six==1.16.0`** → one wheel object, one dependency
  layer, on disk once. The `.blackbox` files each remain individually
  portable; the *cache* is where the sharing happens.
- **Ten packages on Python 3.12** → one interpreter tree.
- **A rebuild that changes only your app code** → same dependency-layer
  digest, zero re-materialization, and a future delta-transfer story for
  free (send the digest set difference).

You can watch it happen:

```
$ blackbox run dup-a.blackbox
BLACKBOX: caching application layer sha256:439e6ac88f4...
BLACKBOX: caching dependencies layer sha256:5cb2d72769e...
$ blackbox run dup-b.blackbox        # same dependency set
BLACKBOX: caching application layer sha256:a1019ca0c20...
                                    # no deps line — layer reused!
```

## Inspecting and maintaining

```bash
blackbox cache             # object count, total bytes, layer + runtime list
blackbox list              # expanded layers and their file counts
blackbox cache --check     # re-hash every object (detects disk rot / tampering)
blackbox cache --clear     # drop objects + layers (runtimes kept)
blackbox doctor            # full health report
```

Corrupted cache objects **self-heal**: the fetch path verifies hashes and
re-downloads anything that fails. If `--check` reports corruption you can't
re-fetch (air-gapped machine), quarantine the object file it names.

## Space

What's big, and what it's shared by:

| Thing | Typical size | Shared |
|---|---|---|
| Python 3.12 runtime | ~60 MB expanded | every 3.12 package |
| Node 22 runtime | ~110 MB expanded | every 22 package |
| Dependency layers | = your app's actual deps | every package with the same dep set |
| Application layers | usually KB–MB | per app version |

Runtimes are the dominant cost and are deduped by design. `blackbox doctor`
lists what's installed; deleting `~/.blackbox/runtimes` is always safe
(they're re-fetched and re-verified on next use).

## Moving a cache / offline seeding

A pre-seeded `~/.blackbox` behaves exactly like a warmed one. Ship a folder
of PBS/Node tarballs and:

```bash
blackbox runtime import cpython-3.12.7+20241002-x86_64-unknown-linux-gnu-install_only.tar.gz
```

Everything else (layers) materializes from the packages themselves.

## The remote future of this store

Objects fetched *by digest* with verification-on-arrival means a
`blackbox serve` HTTP mirror, LAN sync, or p2p layer are all just new
*transport* for the same interface — no format change, no trust model
change. See [Roadmap](../roadmap.md).
