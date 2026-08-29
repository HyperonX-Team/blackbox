# Creating a package

You are the **creator**: you have a working project, and you want to hand
someone an appliance, not instructions.

## 1. Start from a template (or not)

```bash
blackbox init myproject          # hello template
blackbox init myapp --template datasift
blackbox init myapi --template node
```

Or add a `blackbox.yaml` to an existing project:

```
myapp/
├── blackbox.yaml        ← the manifest: the one file you must write
├── requirements.txt     ← python deps (or package.json for node; absent for native)
└── src/
    └── main.py
```

A minimal manifest:

```yaml
format_version: "1"
name: myapp
version: "0.1.0"
description: Does a thing with data
publisher: You <you@example.org>

runtime:
  type: python
  version: "3.12"

entrypoint:
  command: python
  args:
    - src/main.py

permissions:
  filesystem:
    read:  ["./input"]
    write: ["./output"]
  network:
    enabled: false
  process:
    spawn: false

interface:
  type: cli
```

Full field reference: [blackbox.yaml manifest](../reference/manifest.md).

## 2. Respect the data contract

A package talks to the outside world through exactly two directories, which
BLACKBOX creates under `<name>-work/` next to where you run it:

| Directory | Env var the app sees | Purpose |
|---|---|---|
| `input/` | `BLACKBOX_INPUT` | read-only by convention; user drops files here |
| `output/` | `BLACKBOX_OUTPUT` | results; the user's takeaway |

Write code that uses those variables, not hardcoded paths:

```python
import os
src_dir = os.environ["BLACKBOX_INPUT"]
out_dir = os.environ["BLACKBOX_OUTPUT"]
```

```js
const out = process.env.BLACKBOX_OUTPUT;   // node
```

Anything else the app tries to write is rejected at run time — declare what
you need, or you don't get it.

## 3. Lock your dependencies

- **Python:** pin exact versions in `requirements.txt`
  (`numpy==2.1.0`, not `numpy>=2`). `blackbox pack` resolves the full tree,
  records exact wheels with SHA-256 hashes into `blackbox.lock`, and bakes
  an installed `site-packages` tree into the package.
- **Node:** use exact versions in `package.json`; `npm install` output becomes
  a content-addressed `node_modules` layer.
- **Native:** your compiled binary *is* the dependency closure — link
  statically (Go does this by default).

`blackbox.lock` is generated, but you should **commit it**: it is the
reproducibility record of your appliance.

!!! warning "source-only packages"
    The MVP resolves wheels only (`--only-binary=:all:`). A dependency that
    publishes no wheel for your target platform can't be packed — vendor a
    pure-python copy, or pick a different library.

## 4. Pack

```bash
cd myapp
blackbox pack
#   resolving dependencies for myapp (python 3.12)...
#   fetching 2 locked package(s)...
#   building dependency layer...
#   wrote myapp.blackbox (143.6 KB)
```

That's it. `myapp.blackbox` is self-contained (except the interpreter, which
recipients fetch once, hash-verified).

### Cross-packing

Build a Linux-targeted package from macOS or Windows:

```bash
blackbox pack --target x86_64-unknown-linux-gnu -o myapp.linux.blackbox
```

Python/Node dependencies resolve for the target platform. A `native` package
must still be *compiled* on (or for) its target — binaries don't cross by
themselves; pack one `.blackbox` per platform.

## 5. Check what you made

```bash
blackbox inspect myapp.blackbox   # manifest, deps, layers, permissions
blackbox verify  myapp.blackbox   # checksums (and signature if present)
blackbox run     myapp.blackbox   # smoke-test it yourself
blackbox unpack  myapp.blackbox ./peek   # look inside
```

## 6. Optional: sign it

```bash
blackbox keygen lab --publisher "Research Lab X"   # once
blackbox sign myapp.blackbox --key lab
# ship lab.pub.pem alongside the file
```

Details: [Signing & trust](signing.md).

## 7. Distribute — freely

Email it, USB it, `scp` it, drop it on a website or torrent. There is no
registry to ask permission from; nobody can take your appliance down by
turning off a server. That's on purpose.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Could not resolve the requested dependencies` | Unpinned/conflicting versions; pin exactly and retry |
| `must be a path relative to the package root` | Permissions can only name `./`-relative paths |
| Package huge | A stale `*.blackbox` or `-work/` inside the source dir is excluded automatically; check you aren't bundling datasets — those belong in `input/`, not the package |
| Works here, fails there | Compare `blackbox doctor` output; check `runtime.target` matches the recipient's platform |
