# Running a package

You are the **recipient**: someone sent you `tool.blackbox`. You need only
the BLACKBOX CLI on your machine.

## The command

```bash
blackbox run tool.blackbox
```

What happens, in order:

1. **Integrity** — every file in the package is re-hashed and checked against
   its recorded SHA-256; the manifest is re-validated. A corrupted download
   fails right here, loudly, not mysteriously at minute three.
2. **Signature** — if the package is signed and contents changed since,
   BLACKBOX *refuses to run it*.
3. **Consent** — the first time you run a package you haven't approved, you
   see exactly what it is and what it asks for:

   ```
   BLACKBOX
   DataSift - CSV cleaning and exploration appliance

   Name:        datasift 0.1.0
   Publisher:   BLACKBOX Examples
   Signature:   VALID - TRUSTED publisher: Research Lab X

   Requests:

     Filesystem:
       + read:   ./input
       + write:  ./output

     Network:
       - disabled

     Host execution:
       - process spawning: restricted

   Run this BLACKBOX? [y/N]
   ```

   Approving remembers the package's **content digest** — change one byte and
   you'll be asked again. Pass `--yes` to skip the prompt, or `blackbox
   verify` first if you want the machine to check what the human approved.
4. **Provisioning** — the declared interpreter (Python 3.12, Node 22, …) is
   taken from `~/.blackbox/runtimes` if present, else downloaded from the
   official source, **verified against its pinned SHA-256**, and installed
   atomically. One download ever, shared by every package using it.
5. **Execution** — layers are expanded (or reused) from the content-addressed
   cache, the environment is scrubbed, the permission policy is enforced, and
   your app starts. The line `BLACKBOX: running <name> [<tier>]` tells you
   which enforcement tier your OS provided.

## Where your data goes in and out

A per-package **work directory** (`tool-work/` beside where you ran it):

```
tool-work/
├── input/    ← drop files the package may read (declare ./input in manifest)
├── output/   ← results appear here
└── _blackbox_tmp/
```

Copy files in from the command line:

```bash
blackbox run --input data.csv tool.blackbox
```

Web appliances (like DataSift) print their URL when ready:

```
BLACKBOX: datasift is live at  http://127.0.0.1:8765
```

Pass arguments through to the app after `--`:

```bash
blackbox run myplot.blackbox -- --height 480
```

Choose another work dir with `--work ~/projects/run1`.

## Verifying without running

```bash
blackbox inspect tool.blackbox   # manifest, dependencies, layers, signature
blackbox verify  tool.blackbox   # integrity: checksums + signature
blackbox unpack  tool.blackbox ./peek   # expand for human inspection
```

`unpack` shows the actual code: `peek/manifest.json`, `peek/blackbox.lock`
(exact versions + hashes), `peek/application/` (your app), `peek/dependencies/`
(what got installed). Audit before you run — everything is inspectable by
design.

## Trusting publishers

```bash
blackbox trust lab.pub.pem --publisher "Research Lab X"
blackbox verify tool.blackbox
# Signature:   VALID - trusted publisher: Research Lab X
```

Trust is a **local, explicit decision** — there is no central authority
deciding who you may run. See [Signing & trust](signing.md).

## What can go wrong (and what it looks like)

BLACKBOX failures are written as a short summary, the facts, a `Try:` section,
and whether anything on your machine changed:

```
BLACKBOX ERROR

Package requires Python 3.12 runtime, but it is not cached and could not be downloaded.

  Attempted:
    ~/.blackbox/runtimes/python/3.12
  Error: <urlopen error timed out>

Try:
  Check your network connection and retry.
  Or seed offline: blackbox runtime import <tarball>
  blackbox doctor

No changes were made to the host system.
```

| Message means | Do |
|---|---|
| `not a readable BLACKBOX package` | Redownload; the transfer truncated |
| `does not match its recorded hash` | The package was altered after build — contact the sender |
| `Refusing to run: the package changed after it was signed` | Security check caught a mismatch — stop |
| `targets aarch64-apple-darwin, but this machine is …` | Wrong-platform package; ask for your platform's build |
| `SANDBOX VIOLATION … filesystem write` | The app tried to write outside its declared paths |
| App itself crashes | Its exit code and traceback are passed through unchanged |

When in doubt, `blackbox doctor` first — it reports platform, cache health,
provisioned runtimes, sandbox capability, and connectivity.

## Offline use

Packages run fully offline once their runtime is cached (and with
`--yes` / an existing approval, no prompts needed). If you need to seed a
machine with no network at all, copy `~/.blackbox` from a machine that has
run the package once, or `blackbox runtime import
cpython-3.12.7+20241002-x86_64-unknown-linux-gnu-install_only.tar.gz`.
