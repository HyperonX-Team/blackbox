# Signing & trust

Integrity tells you a file arrived intact. **Signing** tells you who built it
and that nobody changed it since. BLACKBOX uses Ed25519 (via the
`cryptography` library) — standard, modern, boring, and deliberately *not*
supported by a central authority or web of trust. Trust is your machine's
local decision.

## Publisher: sign your package

```bash
# once: create a keypair
blackbox keygen lab --publisher "Research Lab X"
#   private: ~/.blackbox/keys/lab.key.pem   (keep secret!)
#   public:  ~/.blackbox/keys/lab.pub.pem   (publish alongside your package)

blackbox sign research-repro.blackbox --key lab
# Signed. State: valid  publisher: Research Lab X
```

Signing appends a `signature.json` member — an Ed25519 signature over the
package's **content digest** (SHA-256 over the canonical set of member
hashes). Re-packing changes the content; signing an unpacked copy does not:

```
manifest · lock · layers · checksums  →  content_digest  →  Ed25519 signature
```

Re-sign after every rebuild, and ship the `.pub.pem` (paste it in your
README / download page / paper).

## Recipient: verify and trust

```bash
blackbox verify research-repro.blackbox
```

```
Integrity:   OK
  application.tar.zst      sha256:3ef36ee7ed49c382...
  blackbox.lock            sha256:a71ae98934900d31...
  ...
Signature:   VALID
Content digest: sha256:e6869a155d3e3111...
```

Three states:

| State | Meaning |
|---|---|
| `unsigned` | No signature present. Run anyway at your own judgement — the consent card shows you exactly what it requests |
| `VALID` | Signature checks out under the embedded public key, but you've never pinned that key |
| `VALID - trusted publisher: …` | You pinned that key with `blackbox trust`; this is the same author you approved before |
| `INVALID` | **Stop.** Contents changed after signing — even if checksums were recomputed to match. `blackbox run` refuses outright |

Pinning a key once per publisher:

```bash
blackbox trust lab.pub.pem --publisher "Research Lab X"
```

Keys are matched by **DER fingerprint**, so renaming a publisher can't
hijack a trusted name. The trust store is `~/.blackbox/keys/trusted.json` —
inspect it, edit it, it's yours.

## What signing protects (and what it doesn't)

- ✔ transmission corruption or *substitution* of a published artifact
- ✔ sneaky content edits, even when the attacker recomputes `checksums.json`
  (they can't reforge the signature)
- ✔ provenance: "this appliance came from key X, which I pinned as Lab X"
- ✘ whether the *author* is honest — a valid signature from a malicious
  publisher is a warning light, not a green one
- ✘ the *contents of dependencies*, beyond their pinned hashes. The lock
  proves the recipient ran the same bytes the author did; it can't prove the
  bytes are benign. (Attestation/transparency work is on the
  [roadmap](../roadmap.md).)

!!! tip "Workflow for papers"
    Publish `analysis.blackbox` + `analysis.pub.pem` + the key fingerprint in
    the paper's supplement. A reviewer runs `blackbox trust`,
    `blackbox verify`, `blackbox run` — and knows the numbers came from the
    sealed environment the authors actually ran.
