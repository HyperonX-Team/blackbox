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

**Prebuilt downloads (recommended — nothing else to install):** every release
ships both the `blackbox` CLI and the `blackbox-gui` desktop app, for every
platform. Grab them from
[GitHub Releases](https://github.com/HyperonX-Team/blackbox/releases).

| Platform | Format | What's inside |
|----------|--------|---------------|
| Linux x86_64 | `blackbox_<ver>_amd64.deb` + `blackbox-gui_<ver>_amd64.deb` | CLI + GUI |
| Linux arm64 | `blackbox_<ver>_arm64.deb` + `blackbox-gui_<ver>_arm64.deb` | CLI + GUI |
| Linux (any) | `blackbox-linux-<arch>.tar.gz` | `blackbox` + `blackbox-gui` |
| macOS (Apple Silicon) | `blackbox-macos-aarch64.tar.gz` | `blackbox` + `blackbox-gui` |
| Windows x86_64 | `blackbox-windows-x86_64.zip` | `blackbox.exe` + `blackbox-gui.exe` |
| Any | raw `blackbox-*` / `blackbox-gui-*` | single binaries |

**Debian / Ubuntu:**
```bash
sudo apt install ./blackbox_*_amd64.deb ./blackbox-gui_*_amd64.deb
blackbox doctor
blackbox-gui            # launch the desktop app (appears in your menu too)
```

**Portable tarball (Linux / macOS):**
```bash
tar xzf blackbox-linux-x86_64.tar.gz
sudo install -m755 blackbox-linux-x86_64/blackbox /usr/local/bin/blackbox
sudo install -m755 blackbox-linux-x86_64/blackbox-gui /usr/local/bin/blackbox-gui
blackbox doctor
```
```bash
# macOS: first launch may need to clear quarantine
xattr -d com.apple.quarantine blackbox-macos-aarch64/blackbox
xattr -d com.apple.quarantine blackbox-macos-aarch64/blackbox-gui
```

**Windows:** unzip `blackbox-windows-x86_64.zip` and run `blackbox.exe`
(command line) or `blackbox-gui.exe` (desktop app).

Verify any download against `SHA256SUMS.txt` from the same release.

Releases are cut automatically by GitHub Actions:

* every push to `main` → `v<crate>-build.<n>` release with all binaries,
  `.deb` packages, `.tar.gz`/`.zip` archives, `SHA256SUMS.txt` and
  per-platform example appliances;
* a tag like `v0.2.0` (must match `Cargo.toml`) → the versioned release.

**Python route** — Python 3.9+ on the machine *running* BLACKBOX (the CLI itself). Package
recipients never need any language runtime on the host — BLACKBOX brings its
own, verified interpreters into `~/.blackbox`.

**Rust route (this rewrite)** — `blackbox` is now a **single native binary**;
nothing to install on the machine *running* the CLI either (no Python, no
nothing):

```bash
cargo build --release
# -> target/release/blackbox  (also: target/x86_64-pc-windows-gnu/release/blackbox.exe)
./target/release/blackbox doctor
```

Then:

```bash
pip install blackbox-runtime      # Python route only, if you prefer
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
src/                 the runtime & CLI (Rust, single static binary)
  main.rs            clap CLI entry point
  commands.rs        all blackbox subcommands
  gui/               desktop GUI (egui) — project manager + YAML editor + pack/run
    main.rs          blackbox-gui binary entry point
    app.rs           application state & event loop
    manifest_editor.rs  visual + raw YAML manifest editor
    project_list.rs  project sidebar
    pack_dialog.rs   pack dialog (target, thin, watch)
    run_dialog.rs    run dialog (work dir, inputs, entrypoint)
    log_view.rs      live output log panel
    settings.rs      theme, projects dir, mirrors
  packaging.rs       deterministic zip/tar format · builder · reader
  manifest.rs        blackbox.yaml parsing + strict validation
  dependency.rs      lock resolution (pip/npm), hash-verified fetch
  runtime.rs         providers: python · node · native · wasm · rust
  runtime_runner.rs  launch, isolation, capture
  sandbox.rs         policy + bwrap/sandbox-exec jails + shim install
  storage.rs         content-addressed store (CAS) + mirror fetchers
  crypto.rs          Ed25519 signing · X25519 + AES-256-GCM sealing
examples/            hello · datasift · research-repro (legacy Python templates still embedded)
tests/               Rust integration tests (determinism, tamper, sign, e2e run)
blackbox/            the previous Python reference implementation
docs/                architecture · format · security · roadmap
docs-site/           static how-to-use site deployed to GitHub Pages
packaging/           make-deb.sh (.deb builder) · blackbox-gui.desktop · PyInstaller spec
```

## Desktop GUI (optional)

The `blackbox-gui` binary is a visual project manager, manifest editor and
pack/run front-end built with [egui](https://github.com/emilk/egui). It is
feature-gated so the zero-dependency CLI build is unaffected.

**Prebuilt** — every release includes it: `blackbox-gui_<ver>_<arch>.deb` on
Linux, `blackbox-gui` inside the `.tar.gz` on Linux/macOS, and
`blackbox-gui.exe` inside the `.zip` on Windows (see [Install](#install)).

```bash
# build from source (first build is slow — egui + eframe)
cargo build --release --features gui --bin blackbox-gui

# run
./target/release/blackbox-gui
```

What it does:

* **Projects sidebar** — create projects from templates, filter, open folders,
  right-click to delete.
* **Manifest editor** — switch between a validated *visual form* and *raw YAML*.
  Errors are shown inline; `Ctrl+S` saves.
* **Pack dialog** — pick output path, target triple, thin mode, watch mode.
* **Run dialog** — work dir, input files, entrypoint subcommand, `--yes`,
  `--data`, `--log`, and app arguments.
* **Live log** — captured stdout/stderr with level filter, text filter and
  auto-scroll.
* **File watching** — external edits to `blackbox.yaml` reload into the editor.
* **Settings** — theme, projects directory, default target, mirror URLs.

The GUI calls the same library functions as the CLI (`packaging::pack`,
`packaging::prepare_run`, `runtime::execute_capture`), so packages produced in
the GUI are byte-identical to `blackbox pack`.

## Documentation site

The how-to-use site lives in [`docs-site/`](docs-site/) as a single static
`index.html` (no build step, no mkdocs). It is published to GitHub Pages at
<https://hyperonx-team.github.io/blackbox/> by
[`.github/workflows/pages.yml`](.github/workflows/pages.yml) on every push to
`main`.

The workflow pushes the site to a `gh-pages` branch (rather than using the
`actions/deploy-pages` environment) so it is not blocked by `github-pages`
environment protection rules. One-time repo setup: **Settings → Pages → Build
and deployment → Source = “Deploy from a branch”, Branch = `gh-pages` / `(root)`**.

Preview locally with any static server:

```bash
cd docs-site && python -m http.server 8000
```

## New in the Rust rewrite (v0.2)

The port keeps byte-compatible formats and adds a stack of capabilities:

* **WASM runtime** — `runtime: {type: wasm, version: "24.0.0"}` wraps a
  wasmtime binary (pinned via GitHub release digests) around a `.wasm`
  entrypoint. WASM is its own sandbox.
* **Rust runtime** — `runtime: {type: rust, version: "1.85"}` compiles
  `src/main.rs` at pack time with a pinned, hash-verified rust toolchain
  (cross-compiles to any target by pulling `rust-std`).
* **Multi-target fat packages** — `runtime.targets: [...]` builds one package
  with per-target dependency layers; the right layer is picked at run time.
* **Thin packages + LAN mirrors** — `pack --thin` emits manifest+index only;
  `blackbox serve` exposes CAS objects by digest; `fetch --mirror …` /
  `blackbox publish` materialize or push layer objects (zero cloud).
* **Whole-package encryption** — `blackbox encrypt pkg --key`/`--to` seals
  layer members (X25519 + AES-256-GCM); `blackbox run`
  decrypts transparently with the matching `*.seal.key.pem`.
* **Composite pipelines** — `blackbox compose --manifest` builds a
  pipeline package out of staged `.blackbox` projects; `run` wires each
  stage's `output/` into the next stage's `input/`.
* **SBOM export** — `blackbox sbom pkg --format spdx|cyclonedx` from the lockfile.
* **Signed binary self-update** — `blackbox self-update <url>` verifies a
  publisher signature over the new binary and swaps it atomically.
* **Zero-install CLI** — the tool itself is a single static binary;
  runtime providers keep the "recipient installs nothing" contract.

## License & contributing

Apache-2.0 (see [LICENSE](LICENSE)). Contributions and threat-model
discussions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).
