# Contributing to BLACKBOX

BLACKBOX is Apache-2.0 licensed and open to contribution big and small:
bug fixes, docs, new runtime providers, tests, and—above all—honest
criticism of the design.

## Ground rules (from the engineering constitution in the project brief)

1. Prefer boring, proven technologies over clever inventions.
2. Keep components replaceable; layers consume only the layer below.
3. The cloud is never a required dependency. An account is never required.
4. Never silently access host resources; defaults stay deny-all.
5. Fail safely, and make the error text readable by a tired human.
6. The `.blackbox` format is open, documented, and stays that way — format
   changes require a `format_version` bump and a spec section in
   `docs/format.md`.
7. Use mature cryptography. Do not invent cryptography.
8. No abstractions that aren't earning their complexity.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]" || pip install -e . pyyaml cryptography zstandard pytest
blackbox doctor
pytest tests -q
```

The integration suite provisions real runtimes (python-build-standalone,
Node.js) on first use; later runs reuse the test cache. Tests that require
network skip cleanly when offline.

## How the codebase is organized

See `docs/architecture.md`. The short version:

* `blackbox/manifest/` — validation only; strict and loud.
* `blackbox/deterministic.py` — if it affects bytes, it belongs here.
  **Every build change must keep packs byte-identical** (`test_pack_is_deterministic`).
* `blackbox/packaging/` — the format. Changing member layout = changing spec.
* `blackbox/runtime/providers.py` — add a language here, plus a schema
  entry in `manifest/schema.py` (RUNTIME_VERSIONS) and integration tests.
* `blackbox/sandbox/` — policy + jails + shim. Security claims belong in
  `docs/security.md` **and must be true**.

## Pull requests

* Open an issue first for anything that changes the format, CLI surface,
  or security model.
* Include tests: every failure mode in the table in `docs/security.md`
  should map to at least one test.
* Run the full suite and paste results; note your platform from
  `blackbox doctor`.
* Keep commits small; the message should say *what* and the body *why*.
* Commits must be signed off (`git commit -s`) under the DCO.

## Adding a runtime provider (mini-guide)

```python
class MyProvider(Provider):
    type = "mylang"
    def supports(self, version): ...
    def pin_for_lock(self, version, target): ...   # exact version + sha256
    def ensure(self, version, target, pin, quiet): ...  # download/verify/extract -> exe path
    def env(self, exe, site_dir, app_dir, target): ...
    def resolve_command(self, command, args, exe, app_dir): ...
PROVIDERS["mylang"] = MyProvider()
```

Requirements: the interpreter must come from an official, hash-verifiable
distribution; provisioning must be atomic; failure must produce the
`BLACKBOX ERROR` format with a `Try:` section. Look at `node` (lock-time
pinning) and `native` (zero-runtime) as reference implementations.

## What we will not merge

* Features requiring accounts, telemetry, or hosted services in the core loop.
* Format changes without spec + versioning + migration story.
* "Security" claims that outrun the enforcement actually implemented.
* Blockchain, tokens, marketplaces. This line is non-negotiable and in the brief.

Thanks for helping make "Download a machine" real.
