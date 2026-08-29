# BLACKBOX Roadmap

The MVP ships one loop done properly: **pack → transfer → run**, in a file,
offline-first, deduplicated, reproducible, permissioned. Everything below is
ordered by what sharpens that loop first. Design decisions in the MVP are
meant to make each of these an *addition*, not a rewrite — the seams are
named in architecture.md.

## v0.2 — make the loop faster and stricter (next)

* **Hardened Linux jail**: seccomp filter + cgroup v2 limits (CPU/mem/PID)
  layered under bwrap; `--sandbox-deny-bind` style host-path blocking for
  reads, not just writes.
* **Windows Tier 1 jail**: AppContainer + restricted tokens; job objects for
  resource limits. Removes the `[environment isolation only]` fallback.
* **Node & native in-process guards**: a preload that enforces network/spawn
  policy for Node (CJS loader hook), and LD_PRELOAD/DYLD interposition for
  native binaries on Unix.
* **`blackbox diff A.blackbox B.blackbox`**: layer-level set difference —
  the read-only groundwork for delta updates, using only existing digests.
* **Registry-free distribution helpers**: `blackbox serve .` → a
  read-only HTTP object/package server for LAN sharing (no accounts);
  recipients add a source with `blackbox config add-source http://lan/…`.
* **Signed release binaries**: codesign + notarize the standalone CLI
  (macOS Gatekeeper, Windows SmartScreen) so the first-run story is as clean
  as the package story; today CI releases unsigned binaries with a documented
  `xattr` workaround.

## v0.3 — languages and platforms

* More runtime **providers** (one class each): Rust (rustup toolchains),
  R, Julia (juliaup tarballs), Deno/Bun.
* **WASM provider**: bundled wasmtime + `.wasm` entrypoint — a portable
  sandbox that does not depend on OS jails at all, and the first runtime
  that works identically on every OS.
* Full **Windows creator** support (cross-resolve/cross-pack already works).
* `blackbox build --target <triple>` producing per-target packages from one
  source in a single command.

## v0.4 — scale and reuse

* **Remote object sources** under `CAS.get`: `http(s)://` lazy fetch by
  digest → thin packages (`manifest + references`) for large apps while
  fat single-file packages remain available.
* **Delta transfer**: reuse layer diff to fetch only missing objects.
* **Peer/LAN discovery** (`lan://` source). P2P (`p2p://`) is explicitly
  deferred until there is real demand; the digest-keyed store means it needs
  no format change.
* **Shared caches** for CI: read-only CAS mirrors.

## v1.0 — the surface people touch

* **Desktop launcher**: double-click a `.blackbox`, see the consent card as a
  real window, click Run/Open. The security-UX mockup in the brief is exactly
  the CLI consent card we ship today, reimplemented in a window.
* **`interface.type: desktop`** for GUI apps (X11/Wayland/Win32 pass-through
  rules in the jail policy).
* **Composition**: `composite` packages chaining `output/ → input/`
  (data-cleaner → simulation → visualizer) — the filesystem contract already
  matches this model.
* **Provenance**: in-toto/SLSA-style attestations recorded in the lockfile;
  optional public transparency for publisher keys.

## Explicitly out of scope (for all of the above)

No app store. No accounts. No tokens/blockchain/"economy". No central
registry dependency. No Kubernetes/orchestration. If a feature only makes
sense with a server we own, it is not BLACKBOX.

The constant is the brief's thesis: **a researcher sends one file; another
researcher opens it; the experiment runs.**
