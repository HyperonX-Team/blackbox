# Multi-language

BLACKBOX is not a Python tool wearing a trench coat. Languages are
**runtime providers**: a provider pins an official interpreter, verifies it
by hash, provisions it into the shared cache, and shapes the execution
environment. Everything else — packaging, layers, CAS, sandboxing, signing —
is language-agnostic.

Today's providers: `python`, `node`, `native` (anything you can compile).

## Node.js

```yaml
runtime:
  type: node
  version: "22"          # LTS majors: 18, 20, 22, 24

entrypoint:
  command: node
  args:
    - src/index.js
```

Dependencies come from `package.json` (exact versions recommended):

```json
{ "name": "wordcount", "version": "1.0.0",
  "dependencies": { "minimist": "1.2.8" } }
```

At pack time BLACKBOX runs `npm install` into an isolated directory and bakes
the resulting `node_modules` tree into a content-addressed dependency layer,
just like Python's site-packages. The Node interpreter itself is pinned into
`blackbox.lock` — **exact version and SHA-256 resolved at pack time from the
official nodejs.org index** — so a package built today provisions byte-for-byte
the same interpreter next year.

`blackbox init myapi --template node` gives you a starter.

Runtime env: the app sees `NODE_PATH` pointed at its own layer, a scrubbed
`PATH`, and the usual `BLACKBOX_INPUT` / `BLACKBOX_OUTPUT` contract.

## Native — Rust, Go, C, Zig, anything compiled

There is no interpreter: your executable *is* the runtime.

```yaml
runtime:
  type: native

entrypoint:
  command: ./bin/solver      # must be inside the package
  args: []
```

Build the binary for your platform, drop it in `bin/`, pack:

=== "Go"

    ```bash
    go build -o bin/solver ./src
    blackbox pack
    ```

=== "Rust"

    ```bash
    cargo build --release
    cp target/release/solver bin/
    blackbox pack
    ```

=== "C"

    ```bash
    cc -O2 -static -o bin/solver src/solver.c
    blackbox pack
    ```

Notes:

- Binaries are platform-specific, so **one `.blackbox` per target**
  (Linux x86_64, macOS ARM64, Windows x86_64…). The manifest's
  `runtime.target` is checked before execution and a mismatch fails with a
  clear message, never a segfault.
- Link **statically** (default in Go; `-static` for C;
  `x86_64-unknown-linux-musl` for Rust). Anything you don't bundle, you may
  not have on the recipient's machine.
- Executable bits survive packaging (they're recorded in the layer index).
- The app follows the same `BLACKBOX_INPUT`/`BLACKBOX_OUTPUT`/`TMPDIR`
  environment contract.
- Enforcement: on Linux/macOS the platform jail (bwrap / sandbox-exec)
  applies to native apps just as it does to interpreters. On Windows there
  is no Tier-1 jail yet, so native runs are labeled
  `[environment isolation only]` — be thoughtful about what native packages
  you approve.

## Python

The default, covered everywhere else in these docs: pinned
python-build-standalone runtimes (3.11/3.12/3.13), `requirements.txt` →
lockfile → wheel layer. See [Creating a package](create.md).

## Adding a language

A provider implements five methods (`supports`, `pin_for_lock`, `ensure`,
`env`, `resolve_command`) — see
[Architecture: runtime providers](../architecture.md#4-runtime-providers-the-multi-language-extension-point).
Hard requirement: the interpreter must come from an official,
hash-verifiable distribution. Candidates in the roadmap: WASM (bundled
wasmtime — a sandbox that doesn't depend on the OS at all), R, Julia, Deno.
