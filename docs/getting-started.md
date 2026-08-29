# Getting Started

## Install the `blackbox` CLI

### Option A — standalone binary (recommended)

No Python, no pip, nothing on your machine gets touched. Download the
binary for your platform from the
[latest release](https://github.com/HyperonX-Team/blackbox/releases):

| Platform | File |
|---|---|
| Linux x86_64 | `blackbox-linux-x86_64` |
| macOS (Apple Silicon) | `blackbox-macos-aarch64` |
| Windows x86_64 | `blackbox-windows-x86_64.exe` |

=== "Linux / macOS"

    ```bash
    chmod +x blackbox-linux-x86_64
    sudo install -m755 blackbox-linux-x86_64 /usr/local/bin/blackbox
    blackbox doctor
    ```

    !!! note "macOS Gatekeeper"
        Release binaries are not yet code-signed, so the first launch may
        need: `xattr -d com.apple.quarantine blackbox-macos-aarch64`

=== "Windows"

    ```powershell
    # e.g. put it in %LOCALAPPDATA%\Programs\blackbox and add that folder to PATH
    blackbox doctor
    ```

### Option B — pip

```bash
pip install blackbox-runtime    # Python 3.9+
blackbox doctor
```

!!! tip "What is the CLI's own Python, then?"
    The CLI needs *a* Python (option B) or bundles its own (option A). This
    is unrelated to the interpreters your **packages** run on: those are
    provisioned separately, hash-verified, into `~/.blackbox/runtimes`.
    The host's Python is never used by an application.

### From a source checkout

```bash
git clone https://github.com/HyperonX-Team/blackbox
cd blackbox
pip install -e ".[dev]"
pytest -m "not heavy"
```

## Verify your installation

```
$ blackbox doctor
BLACKBOX 0.1.0 - doctor

  platform:            x86_64-unknown-linux-gnu
  home:                /home/you/.blackbox  [writable]
  host python:         3.12.1 (not used by packages)
  runtime python 3.12: not cached (downloaded on first use)
  sandbox:             bwrap
  libraries:           ok (yaml, cryptography, zstandard)
  network (pypi):      reachable

  everything looks healthy
```

## Your first BLACKBOX (60 seconds)

```bash
blackbox init hello
cd hello
blackbox pack                # -> hello.blackbox
blackbox run hello.blackbox  # first run provisions Python 3.12, then executes
```

You'll see a permission summary before the first run of a package (name,
publisher, what it can read/write, whether it can use the network), then:

```
BLACKBOX: running hello 0.1.0 [platform jail + runtime shim]
Hello from inside a BLACKBOX!
  python:     3.12.7
```

Note the `[platform jail + runtime shim]` label — BLACKBOX always tells you
*which* enforcement tier the OS actually gave it. See
[Security model](security.md).

## A more interesting first: DataSift

```bash
blackbox init myapp --template datasift
cd myapp
blackbox pack
blackbox run datasift.blackbox
# BLACKBOX: datasift is live at  http://127.0.0.1:8765
```

Open the URL, load a CSV (from `input/` or upload one), inspect columns,
filter, and export a cleaned file to `output/clean.csv`. Then hand the single
`datasift.blackbox` file to a colleague — they need nothing installed but
the CLI.

## What next?

- Package your own project → [Creating a package](guide/create.md)
- Understand the run experience → [Running a package](guide/run.md)
- Node.js or compiled binaries → [Multi-language](guide/multi-language.md)
