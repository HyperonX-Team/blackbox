# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (MVP) | Yes |

## Reporting a vulnerability

Please report security issues **privately** before public disclosure:

* GitHub security advisories: https://github.com/blackbox-project/blackbox/security/advisories/new
* Or email the maintainers via the contact listed on the repo.

Include: BLACKBOX version, platform (run `blackbox doctor` and paste the
output), a minimal reproduction, and what you believe the security impact is.

Expect an acknowledgement within 5 business days. We will coordinate a fix
and disclosure timeline with you.

## What we consider a vulnerability

* Escape from a declared permission **when a Tier 1 platform jail was
  active** (`blackbox run` printed `[platform jail …]`).
* Execution of code that does not match the package's signature or checksums
  (integrity bypass).
* Path traversal on extract from a crafted package.
* Runtime cache poisoning (an interpreter binary differing from its pinned
  hash being executed).

## What is *within the documented model* (not vulnerabilities)

The MVP's isolation guarantees are deliberately scoped — read
[docs/security.md](docs/security.md) first. In particular:

* Python apps bypassing the **in-process shim** via C extensions or ctypes
  on a machine with **no platform jail active** (Tier 2 is explicitly
  documented as contract-enforcement, not a jail). Use Linux/macOS with the
  jail (`bwrap`/`sandbox-exec`) for real boundaries.
* Native/Node packages escaping the sandbox on Windows, where no Tier 1
  jail exists yet in v0.1 (labeled `[environment isolation only]` at run time).
* A malicious *consented* package doing anything within its granted
  permissions.
* Malice inside genuinely upstream-correct dependencies (what BLACKBOX
  promises is *pinned bytes by hash*, not benign code).

We may still triage such reports as hardening work — when in doubt, report.
