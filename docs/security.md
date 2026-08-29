# BLACKBOX Security Model

> **BLACKBOX sandboxing is an isolation boundary, not automatically a
> formally verified security boundary.** It raises the cost of accidents and
> casual malice and makes package capabilities explicit and auditable. It
> does not make an untrusted executable from an unknown attacker "safe" to
> run, and it is not a substitute for normal caution with untrusted software.

## Threat model — what the MVP defends against

| Threat | Mitigated? | How |
|---|---|---|
| Accidental over-reach by a well-meaning app (writes outside its folder, phones home) | **Yes** | default-deny permissions + consent gate + shim/jail |
| Silent, undeclared host access | **Yes** | filesystem paths in the manifest must be `./`-relative; anything else is rejected at pack time |
| Corrupted / partially transferred package | **Yes** | `checksums.json` over every member, verified on open |
| Package modified after publishing (content swap) | **Yes** | Ed25519 signature over the content digest; run refuses INVALID |
| Attacker edits content *and* recomputes checksums | **Yes** | they cannot reforge the signature; verify/run detect the mismatch |
| Downloaded interpreter swapped/tampered | **Yes** | every runtime is hash-verified against a pinned upstream sha256 before it is ever executed |
| Path traversal inside a malicious ZIP/TAR (`../../.ssh/keys`) | **Yes** | member paths validated on extract; absolute/`..` rejected |
| A determined, root-privilege local adversary *on the recipient's own machine* | **Partly** | depends on the platform jail; see "not defended" below |
| Malicious *publisher* running arbitrary permitted code | **No** | the app still does what its author wrote within its granted capabilities; that's the point of the consent card |

## Capability model

Every BLACKBOX starts from **deny-all** and must explicitly request more:

```yaml
permissions:
  filesystem:
    read:  ["./input"]     # only ./-relative, package-scoped paths
    write: ["./output"]
  network:   {enabled: false}
  process:   {spawn: false}
```

At run time `./input`/`./output` resolve under a per-package *work directory*
(the host paths a user actually sees); the app's `HOME` and temp dirs are
redirected there too, so stray writes don't touch the real home.

## Enforcement tiers (best available per platform)

BLACKBOX always uses the strongest tier the OS gives it, and *tells you
which one it used* on every run (`[platform jail + runtime shim]`,
`[runtime shim]`, or `[environment isolation only]`).

### Tier 1 — Platform jail (kernel-enforced)

* **Linux**: [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`)
  if present and functional (we *probe* it — a present-but-blocked bwrap
  degrades honestly to the shim tier) — unshared user/PID/IPC/cgroup
  namespaces, `--unshare-net` whenever `network.enabled: false` (kernel-level
  egress denial), the host mounted **read-only** (`--ro-bind / /`), and
  writable binds created **only** for the granted `filesystem.write` paths
  plus the package work directory. Reads of the broader host filesystem are
  not restricted in the MVP (see limits below); writes and network are.
* **macOS**: `sandbox-exec` with a generated profile (deny file-write*; allow
  only granted subpaths; deny network* unless granted).

### Tier 2 — Runtime shim (in-process; always on for Python)

A `sitecustomize.py` loaded inside the bundled interpreter enforces the
materialized policy: outbound `socket` connects to non-loopback addresses are
blocked when `network.enabled: false`; `subprocess`/`os.exec*`/`os.system`
are blocked when `process.spawn: false`; `open()` for writing outside the
granted roots raises a clear `SANDBOX VIOLATION` (exit code 76) instead of
touching the disk. Node and native packages run with the policy materialized
but no equivalent in-process guard yet — they rely on Tier 1 where present,
or Tier 3.

### Tier 3 — Environment isolation (minimum everywhere)

Even with no jail and no shim (e.g. native binaries on Windows), a run still:
uses a separate interpreter, scrubbed `PATH`/`HOME`/`TMP`, hidden from host
site-packages/`NODE_PATH`, and surfaces a consent card before the first run.
`blackbox run` labels this honestly as `[environment isolation only]`.

## Integrity & provenance

* **Package integrity** — sha256 of every member (`checksums.json`), verified
  on open and by `blackbox verify`.
* **Layer integrity** — each layer's content-address matches its `digest`
  before extraction; the local cache re-hashes on `blackbox cache --check`.
* **Provenance** — optional Ed25519 signatures; a publisher key can be pinned
  so `verify`/`run` show `trusted publisher`. Trust is a *local* decision
  (a keyring file), not a central authority. There is no marketplace and no
  mandatory registry, by design.

## Consent UX

Before the first run of any not-yet-approved package, BLACKBOX prints the
name, publisher, signature state, and the exact capabilities it requests,
and asks `[y/N]`. Approval is remembered keyed by content digest, so editing
the package invalidates the stored approval and re-prompts.

## What is explicitly NOT claimed

* Not a hardened container runtime, not gVisor/Firecracker-class.
* The Python shim is best-effort in-process and can be bypassed by a
  deliberately subverting Python program (C extensions, ctypes, exotic syscalls);
  treat it as *accident-prevention and contract enforcement*, not a jail. For a
  real jail use Tier 1 (Linux/macOS) or run untrusted code in a VM.
* Windows has no Tier 1 jail in the MVP (AppContainer/job objects pending) —
  documented in docs/roadmap.md.
* Supply-chain of *upstream* wheels/npm packages is assumed honest; BLACKBOX
  guarantees they are the exact bytes pinned by hash, not that they are
  benign. A future `--lockfile-transparency` step can record provenance
  metadata without breaking the format.

## Reporting vulnerabilities

See [SECURITY.md](https://github.com/HyperonX-Team/blackbox/blob/main/SECURITY.md).
