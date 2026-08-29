# The `.blackbox` package format — version 1

A `.blackbox` file is a standard **ZIP** archive with fixed, deterministic
member metadata and a documented internal layout. You can open it with `unzip`,
7-Zip, or any ZIP tool; BLACKBOX layers are zstd-compressed TARs and the
human-facing files are YAML/JSON. The format is open: nothing here is
proprietary, and any conforming implementation may read or write it.

## Rules that make a package *deterministic*

The same source + manifest + lockfile MUST produce byte-identical bytes:

* ZIP members are stored in a fixed order (below), with a fixed timestamp
  (1980-01-01 00:00:00), fixed external attrs (mode 0644), no extra fields
  and no archive comment.
* Layer TARs sort members, zero uid/gid/uname/gname, fix mtime, normalise
  file modes to 0644 and directory/exec modes to 0755.
* JSON is canonical: UTF-8, object keys sorted, no insignificant whitespace,
  no floats/doubles (only strings, ints, bools, null, arrays, objects).
* YAML lockfiles are emitted with sorted keys.

## Top-level members (fixed order)

| # | member | present | contents |
|---|---|---|---|
| 1 | `manifest.json`  | always | canonical JSON, normalised manifest (§Manifest) |
| 2 | `blackbox.lock`  | always | YAML lockfile (§Lockfile) |
| 3 | `application.tar.zst` | always | deterministic layer: source + assets (§Layers) |
| 4 | `dependencies.tar.zst` | if any deps | deterministic layer: installed site-packages / node_modules |
| 5 | `layers.json`    | always | canonical JSON layer index (§Layers index) |
| 6 | `checksums.json` | always | canonical JSON: sha256 of every member except itself and `signature.json` |
| 7 | `signature.json` | if signed | canonical JSON Ed25519 signature (§Signing) |

`checksums.json` is the integrity root for content; `signature.json` is the
trust root over that content.

## Manifest (`manifest.json`)

Normalised view of the authoring file `blackbox.yaml`. Keys:

```jsonc
{
  "format_version": "1",
  "name": "datasift",                 // ^[a-z0-9][a-z0-9._-]{0,63}$
  "version": "0.1.0",                 // semver-ish
  "description": "…",
  "publisher": "…",
  "runtime": {
    "type": "python",                 // python | node | native
    "version": "3.12",                // interpreter family; native → "any"
    "target": "x86_64-unknown-linux-gnu"   // build/run target triple
  },
  "entrypoint": { "command": "python", "args": ["src/main.py"] },
  "permissions": {
    "filesystem": { "read": ["./input"], "write": ["./output"] },   // ./-relative only
    "network":    { "enabled": false },
    "process":    { "spawn":    false }
  },
  "environment": { "variables": { "KEY": "value" } },   // values are always strings
  "interface":   { "type": "cli", "port": null },        // cli | web
  "requirements": "requirements.txt"                     // node → "package.json"
}
```

Entrypoint command by runtime type:

* `python` → must be `python` / `python3`; `args[0]` is a script path inside
  the application layer (resolved there at run time). The bundled interpreter
  is used, never the host's.
* `node` → must be `node`; `args[0]` is a `.js` path inside the app layer.
* `native` → must start with `./` and point at a file in the app layer
  (the compiled executable). `args` pass straight through.

### Constraint rules (rejected at pack time, not run time)

* `format_version` must be `1`.
* Filesystem paths must start with `./` and contain no `..` traversal —
  a package can never request an absolute host path.
* Runtime `type`/`version` must be among those the build supports.
* `entrypoint.command` must match the runtime type.

## Lockfile (`blackbox.lock`)

Records the *exact* interpreter identity and every dependency, by hash.

Python:

```yaml
lock_version: 1
runtime: {type: python, version: "3.12", target: x86_64-unknown-linux-gnu}
packages:
- name: jinja2
  version: 3.1.4
  sha256: bc5dd2ab…            # sha256 of the exact wheel
  url:  https://files.pythonhosted.org/…/jinja2-3.1.4-py3-none-any.whl
- name: markupsafe
  version: 3.0.3
  sha256: 26a5784d…
  url:  https://files.pythonhosted.org/…/markupsafe-…-cp312-…-linux_x86_64.whl
```

Node (interpreter pinned into the lock too, because the version is
major-relative):

```yaml
runtime:
  type: node
  version: "22"
  target: x86_64-unknown-linux-gnu
  version_exact: 22.14.0        # resolved at pack time
  asset: node-v22.14.0-linux-x64.tar.gz
  url:  https://nodejs.org/dist/v22.14.0/node-v22.14.0-linux-x64.tar.gz
  sha256: <from upstream SHASUMS256.txt>
packages:
- {name: minimist, version: 1.2.8, integrity: sha512-…}   # from package-lock
```

Native: `packages: []` (the executable carries its dependencies).

The lockfile is the reproducibility contract: fetching verifies each
downloaded artifact against its recorded `sha256`, so a package rebuilds the
same environment even on a machine that never had these versions.

## Layer index (`layers.json`)

```jsonc
{
  "layers": [
    {"kind": "application",  "digest": "sha256:…", "file": "application.tar.zst",
     "members": 4, "bytes": 784, "exec": ["bin/app"]},
    {"kind": "dependencies", "digest": "sha256:…", "file": "dependencies.tar.zst",
     "members": null, "bytes": 140902, "exec": []}
  ]
}
```

* `digest` is `sha256:<hex>` over the raw layer bytes → the content-addressed
  key under which BLACKBOX caches and deduplicates the layer.
* `exec` lists app-layer paths that must be `chmod +x` on extraction (native
  binaries, POSIX launch scripts).
* `kind` maps to an install destination: `application` → the app tree;
  `dependencies` → the site-packages / node_modules tree.

A layer's `digest` MUST equal the sha256 of its ZIP member; run verifies this
before expansion, so a tampered layer inside an otherwise-valid archive is
rejected.

## Checksums (`checksums.json`)

```jsonc
{"sha256": {
  "manifest.json": "<hex>", "blackbox.lock": "<hex>",
  "application.tar.zst": "<hex>", "dependencies.tar.zst": "<hex>",
  "layers.json": "<hex>"
}}
```

Excludes `checksums.json` and `signature.json` themselves. `blackbox verify`
fails if any listed member's hash differs.

## Signing (`signature.json`)

Ed25519 over the **content digest**:

```
content_digest = sha256( canonical_json( { member -> sha256hex } ) )   # checksums, minus signature
```

```jsonc
{
  "alg": "ed25519",
  "publisher": "Research Lab X",
  "public_key": "-----BEGIN PUBLIC KEY-----…",   # PEM, SubjectPublicKeyInfo
  "signature": "<hex of Ed25519 signature over content_digest>",
  "content_digest": "sha256:…"
}
```

Verification checks `content_digest` matches the recomputed one AND the
signature validates under `public_key`. A local trust store maps a publisher
name → expected key fingerprint, so `verify` can upgrade `VALID` to
`VALID - trusted publisher`. Re-signing a package rewrites the ZIP (members
re-emitted in the fixed order) with `signature.json` added — still
deterministic given the same inputs.

## Safety invariants any reader should enforce

* Reject ZIP/TAR members whose resolved path escapes the destination
  (traversal) or is absolute.
* Never execute content whose hash does not match its layer `digest` or a
  member's `checksums.json` entry.
* Treat the manifest as untrusted input for *display* and *consent*; the
  runtime decides enforcement, not the packaged code.
* Fail closed: a missing required member, a bad checksum, or an invalid
  signature must stop execution, not warn and continue.
