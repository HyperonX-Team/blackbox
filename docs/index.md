# BLACKBOX

**Download a machine.**

A BLACKBOX is a program *plus its world* — the runtime, its dependencies, its
interface, its permissions, and its data contract — packaged into one
reproducible, portable `.blackbox` file.

The recipient does not install Python, npm packages, CUDA drivers, or
anything else. They run one command, and BLACKBOX rebuilds the machine around
the application.

```
SOURCE PROJECT          datasift.blackbox           ANOTHER MACHINE
    │                        │                            │
    ├─ blackbox pack ────────┤  USB / email / download ───┤─ blackbox run
    │                        │        (one file)          │       │
    ▼                        ▼                            ▼       ▼
  your code            everything it needs          downloads    app runs
  + manifest           to reproduce itself          nothing      (verified)
```

## Why this exists

The modern way to hand someone a computational tool is still
"clone this repo, make a venv, install requirements, hope your platform
matches." BLACKBOX replaces that with:

> **Download → Open → Run**

- **A file that belongs to you.** No app store, no account, no server.
  A `.blackbox` moves over USB, email, torrent, or `scp` just as well.
- **Reproducible by hash.** Same source + lockfile ⇒ byte-identical package.
  Dependencies pinned by exact versions *and* SHA-256.
- **Deduplicated.** Ten appliances that all use Python 3.12 share one
  runtime on disk, content-addressed.
- **Permissioned.** Packages declare filesystem/network/process access up
  front; defaults deny everything; you approve before the first run.
- **Multi-runtime.** Python and Node.js interpreters are provisioned
  automatically from hash-pinned official builds; `native` packages carry
  their own compiled binary (Rust, Go, C…).

## Try it in one copy-paste

=== "Linux / macOS"

    ```bash
    blackbox init hello && cd hello
    blackbox pack
    blackbox run hello.blackbox
    ```

=== "Windows (PowerShell)"

    ```powershell
    blackbox init hello; cd hello
    blackbox pack
    blackbox run hello.blackbox
    ```

The first `run` downloads a verified CPython 3.12 into `~/.blackbox` —
never your system Python — and every later package reuses it.

## Where to go next

| I want to… | Read |
|---|---|
| Install the CLI | [Getting Started](getting-started.md) |
| Ship my own tool as a `.blackbox` | [Creating a package](guide/create.md) |
| Run / audit a package I received | [Running a package](guide/run.md) |
| Pack a Node.js or compiled app | [Multi-language](guide/multi-language.md) |
| Sign packages so recipients can trust them | [Signing & trust](guide/signing.md) |
| Understand how it all fits together | [Architecture](architecture.md) |
| Implement my own reader/writer | [Package format spec](format.md) |

---

!!! quote "The thesis"
    A researcher sends one file. Another researcher opens it. The experiment
    runs.
