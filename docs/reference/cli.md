# CLI reference

All commands print human-readable errors with a `Try:` section and state
whether the host was modified. `blackbox --help` / `blackbox CMD --help`
mirror this page.

## `blackbox init NAME`

Create a starter project in `NAME/`.

| Flag | Default | Meaning |
|---|---|---|
| `--template {hello,datasift,node}` | `hello` | starting point |
| `--python VER` | `3.12` | runtime version to pin in the manifest |

```bash
blackbox init hello
```

## `blackbox pack [PATH]`

Build `PATH` (default: current directory) into `NAME.blackbox`. Writes/refreshes
`blackbox.lock` next to the manifest. Requires each declared dependency to
publish wheels/binaries for the target platform.

| Flag | Meaning |
|---|---|
| `-o, --output FILE\|DIR` | where the package lands (default: `NAME.blackbox` in the source dir) |
| `--target TRIPLE` | cross-pack, e.g. `x86_64-unknown-linux-gnu` |

```bash
blackbox pack --target x86_64-unknown-linux-gnu -o app.linux.blackbox
```

## `blackbox run [FLAGS] PACKAGE [-- APP_ARGS...]`

Verify → (first-run consent) → provision runtime → materialize layers →
execute under the declared policy. `run` options go **before** the package;
app arguments go after `--`.

| Flag | Meaning |
|---|---|
| `--work DIR` | work directory (default `./NAME-work/`) |
| `--input FILE` | copy file into the package's `input/` (repeatable) |
| `--yes` | skip the permission-confirmation prompt |

Exit codes: the app's own code, `76` for sandbox violations, `1` for BLACKBOX
errors. A `SIGINT`/Ctrl-C terminates the app.

```bash
blackbox run --input data.csv datasift.blackbox
blackbox run plot.blackbox -- --height 480
```

## `blackbox inspect PACKAGE`

Pretty-print manifest, dependencies, layers (digest + size), signature state,
and content digest.

## `blackbox verify PACKAGE`

Re-hash every member; verify the signature if present. Non-zero exit on any
failure. Use before running anything you didn't build.

## `blackbox unpack PACKAGE [DEST]`

Expand to `DEST/` for auditing: `manifest.json`, `blackbox.lock`,
`checksums.json`, `signature.json`, plus expanded `application/` and
`dependencies/` trees.

## `blackbox list`

Show cached, expanded layers with file counts.

## `blackbox cache [--clear | --check]`

Cache statistics (objects, bytes, layers, runtimes), `--check` re-hashes the
whole content-addressed store, `--clear` drops objects + layers (runtimes
kept).

## `blackbox doctor`

Health report: platform triple, home writability, host Python (noted as
unused by packages), provisioned runtimes, sandbox capability (`bwrap` /
`sandbox-exec` / `shim-only`), required libraries, network reachability.

## `blackbox keygen NAME [--publisher P]`

Create an Ed25519 keypair in `~/.blackbox/keys/`. The `.pub.pem` is what you
publish.

## `blackbox sign PACKAGE --key NAME`

Append `signature.json` (Ed25519 over the content digest). Re-sign after each
repack.

## `blackbox trust PUBKEY_FILE --publisher P`

Pin a publisher's public key locally, by DER fingerprint.

## `blackbox runtime list`

Show installed/pinnable interpreters.

## `blackbox runtime import TARBALL`

Offline seeding: install a python-build-standalone `install_only` tarball
(verified against its `.sha256` sidecar if present) into the runtime cache.

## Global flags

- `--version` — print CLI version.
- `BLACKBOX_HOME` env var — relocate the entire cache (`~/.blackbox`).
- `BLACKBOX_SANDBOX_ENFORCE=0` — development/testing escape hatch that turns
  the Python shim into a warn-only mode (jails are unaffected).
