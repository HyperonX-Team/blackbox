# `blackbox.yaml` manifest reference

The manifest is the contract between creator and runtime. Validation is
**strict**: unknown runtime types, malformed names, absolute or traversal
permission paths, and entrypoint/command mismatches fail at pack time — you
never discover them on a recipient's machine.

```yaml
format_version: "1"
name: myapp
version: "0.1.0"
description: Optional one-liner shown in inspect + consent cards
publisher: You <you@example.org>

runtime:
  type: python          # python | node | native
  version: "3.12"       # 3.11/3.12/3.13 · node: 18/20/22/24 · native: any/""

entrypoint:
  command: python       # python | node | ./bin/exe  (must match runtime.type)
  args: [src/main.py]

permissions:
  filesystem:
    read:  ["./input"]
    write: ["./output"]
  network: {enabled: false}
  process: {spawn: false}

environment:
  variables:
    APP_MODE: production

interface:
  type: cli             # cli | web
  port: null            # hint for web apps

requirements: requirements.txt   # node default: package.json
```

## Field rules

| Field | Rule |
|---|---|
| `name` | `[a-z0-9][a-z0-9._-]{0,63}` |
| `version` | semantic-version-ish (`0.1.0`, `1.2.3-rc1`) |
| `format_version` | must be `"1"` for this build |
| `runtime.target` | platform triple; defaults to the **build host**; validated against the support list (`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-pc-windows-msvc`) |
| `environment.variables` | valid env-var names; values are coerced to **strings** (quote YAML booleans: `"on"`, not `on` — bare `on` parses as `true`!) |

### Entrypoint by runtime

| `runtime.type` | allowed `command` | `args[0]` resolves as |
|---|---|---|
| `python` | `python` / `python3` | script path in the application layer |
| `node` | `node` | `.js` path in the application layer |
| `native` | `./relative/path` inside the package | the executable itself |

### Permissions

- `filesystem.read` / `filesystem.write`: lists of `./`-relative paths only.
  `..` and absolute paths are rejected — **a package cannot request your
  home directory by name**; it gets `./input`/`./output` under its work dir.
- `network.enabled: false` (default) ⇒ non-loopback outbound connections are
  blocked; `true` ⇒ allowed (and clearly shown in the consent card).
- `process.spawn: false` (default) ⇒ `subprocess`/`os.exec*` blocked
  (Python tier); `true` ⇒ allowed.

Defaults deny everything; every grant is explicit, visible, and part of the
signed content digest.

## What the manifest becomes

At pack time the normalized manifest is written as canonical JSON
(`manifest.json`) inside the package — the YAML above is your authoring
surface; the canonical JSON is the wire format other tools can implement.
Every byte is covered by `checksums.json`, and the set of member hashes forms
the content digest that signatures commit to.
