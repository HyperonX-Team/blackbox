<p align="center">
  <img src="docs/assets/blackbox-logo.svg" width="110" alt="BLACKBOX logo">
  <h1 align="center">BLACKBOX</h1>
</p>

**Download a machine.**

 **Documentation: <https://hyperonx-team.github.io/blackbox/>**

A BLACKBOX is a program + its runtime + its dependencies + its interface +
its permissions, packaged into one reproducible, portable `.blackbox` file.
The recipient does not install Python, npm packages, or anything else —
they run the file and BLACKBOX rebuilds the machine around it.

```
SOURCE PROJECT          datasift.blackbox           ANOTHER MACHINE
    │                        │                            │
    ├─ blackbox pack ────────┤  USB / email / download ───┤─ blackbox run
    │                        │        (one file)          │       │
    ▼                        ▼                            ▼       ▼
  your code            everything it needs          downloads    app runs
  + manifest           to reproduce itself          nothing      (verified)
```

* **Open format** — a `.blackbox` is a documented, inspectable archive (see [docs/format.md](docs/format.md)).
* **Content-addressed** — layers are deduplicated by SHA-256. Ten apps, one Python 3.12, one NumPy.
* **Reproducible** — deterministic builds: identical source + lockfile ⇒ byte-identical package.
* **Permission-first** — packages declare filesystem/network/process access; defaults deny everything.
* **Offline forever** — no account, no server, no registry. The file is the product.
* **Multi-runtime** — Python and Node.js provisioned automatically from hash-pinned upstream builds; `native` packages carry their own compiled binary (Rust, Go, C…).

---

## Install

**Prebuilt binaries (recommended — nothing else to install):** grab
`blackbox-linux-x86_64`, `blackbox-macos-aarch64`, or
`blackbox-windows-x86_64.exe` from [GitHub Releases](https://github.com/blackbox-project/blackbox/releases),
then:

```bash
chmod +x blackbox-linux-x86_64
sudo install -m755 blackbox-linux-x86_64 /usr/local/bin/blackbox   # on PATH, done
blackbox doctor
```

(The macOS binary is unsigned in v0.1: first run may need
`xattr -d com.apple.quarantine blackbox-macos-aarch64`.)

**Python route** — Python 3.9+ on the machine *running* BLACKBOX (the CLI itself). Package
recipients never need any language runtime on the host — BLACKBOX brings its
own, verified interpreters into `~/.blackbox`.

```bash
pip install blackbox-runtime      # (from PyPI, once published)
# or from a checkout:
pip install .
blackbox doctor                   # sanity-check platform, cache, sandbox
```

Primary support: Linux x86_64, macOS ARM64. macOS x86_64 and Windows x86_64
work today (Windows lacks a kernel-level jail — see [docs/security.md](docs/security.md)).

## Five-minute quickstart

```bash
blackbox init hello
cd hello
blackbox pack                 # -> hello.blackbox
blackbox run hello.blackbox   # provisions Python 3.12.7 on first run, then executes
```

Ship `hello.blackbox` to a colleague by any means. They run:

```bash
blackbox run hello.blackbox
```

and the app starts. Their host Python is never used or consulted.

## The demos

### `datasift` — a CSV cleaning appliance (web UI, stdlib only)

```bash
cp -r examples/datasift myapp && cd myapp
blackbox pack
blackbox run datasift.blackbox
# BLACKBOX: datasift is live at  http://127.0.0.1:8765
```

Load a CSV (from `input/` or by uploading), inspect types/missingness,
filter rows, get statistics, export a cleaned CSV to `output/clean.csv`.
No third-party dependencies at all — which is exactly the point: the
recipient installs *nothing*, not even via the package.

### `research-repro` — a sealed research environment (pip dependencies)

```bash
cp -r examples/research-repro repro && cd repro
blackbox pack          # resolves jinja2==3.1.4 (+markupsafe) by hash
blackbox run research-repro.blackbox
# -> output/report.html, output/metrics.json, output/figures/*.svg
```

The report is rendered with the *exact* dependency versions (pinned by
sha256 in `blackbox.lock`) on an interpreter downloaded and verified on the
recipient's machine. Send the file with your paper; reviewers reproduce the
analysis with `blackbox run`.

### Multi-language

```bash
blackbox init wordy --template node   # style Node app (see tests for package.json example)
```

* **Node.js**: `runtime: {type: node, version: "22"}` — the official nodejs.org
  distribution is pinned (version + sha256) into the lockfile at pack time and
  verified at first run; npm dependencies become a shared dependency layer.
* **Native** (Rust, Go, C, …): `runtime: {type: native}` with
  `entrypoint: {command: ./bin/app}` — your compiled binary *is* the runtime;
  it lives in the content-addressed application layer.
* Adding another language = adding one runtime provider class
  (see [docs/architecture.md](docs/architecture.md#runtime-providers)).

## Reading a package

```bash
blackbox inspect datasift.blackbox   # manifest, deps, layers, permissions, signature
blackbox verify  datasift.blackbox   # checksums + signature; rc!=1 if tampered
blackbox unpack  datasift.blackbox   ./peek   # expand everything for humans
```

## Trust & signing (optional)

```bash
blackbox keygen lab --publisher "Research Lab X"
blackbox sign   research-repro.blackbox --key lab
# publish lab.pub.pem alongside the package
blackbox trust  lab.pub.pem --publisher "Research Lab X"
blackbox verify research-repro.blackbox   # -> Signature: VALID - trusted publisher
```

BLACKBOX refuses to run a package whose contents changed after signing.
Before the *first* run of any unsigned package, you see exactly what it
requests (filesystem/network/process) and approve or cancel; approvals are
remembered per content digest.

## Cache & deduplication

```bash
blackbox cache            # statistics: objects, bytes, layers, runtimes
blackbox cache --check    # re-hash every cached object (detects disk rot)
blackbox list             # installed layers
```

Layers (runtimes, dependency bundles, app trees) live in a content-addressed
store under `~/.blackbox/objects/sha256/…`. Two apps that use Python 3.12 and
`six==1.16.0` share both, byte-for-byte, on disk — while remaining
individually portable as single files.

## How it works (60 seconds)

1. **pack** resolves dependencies (pip/npm against the *target* platform),
   pins exact versions+hashes in `blackbox.lock`, expands them into a
   deterministic, zstd-compressed layer, and writes a sorted, fixed-timestamp
   ZIP: `manifest.json + lock + layers + checksums (+ signature)`.
2. **run** verifies checksums (and signature), fetches/verifies the declared
   interpreter from the pinned upstream build (first use only), materializes
   layers from the shared cache, scrubs the environment, enforces the
   declared permissions (platform jail where available + in-process shim),
   and execs the entrypoint.
3. Errors are written for humans, with a `Try:` section, and say whether
   anything changed on your machine.

## Non-goals

No app store. No accounts. No cloud dependency. No tokens or blockchain.
Not a Docker replacement for fleets — it's the "click two things, run the
science" layer for individuals. (Roadmap in [docs/roadmap.md](docs/roadmap.md).)

## Layout

```
blackbox/            the runtime & CLI (Python)
  cli/ packaging/ manifest/ dependency/
  runtime/ (providers: python, node, native)
  sandbox/ (policy + platform jails + shim)
  storage/ (content-addressed store)  crypto/ (Ed25519 signing)
examples/            hello · datasift · research-repro
tests/               unit + integration (incl. tamper & permission-denial)
docs/                architecture · format · security · roadmap
```

## License & contributing

Apache-2.0 (see [LICENSE](LICENSE)). Contributions and threat-model
discussions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).
