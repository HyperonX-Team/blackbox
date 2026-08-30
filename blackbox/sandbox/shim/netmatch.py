"""Hostname allowlist matching shared by the sandbox shims.

A pattern matches a host when:
  * pattern == host (exact), or
  * pattern starts with '*.' and host equals the suffix or ends with '.' + suffix.

Matching is case-insensitive and applied to the hostname the application tried
to connect to, BEFORE DNS resolution. This is a contract enforcement (the same
tier as the rest of the shim), not a DNS-security boundary: a resolved-IP check
cannot be done portably in-process. The platform jail (where available) is the
stronger tier.
"""

import fnmatch


def host_allowed(host, allowlist) -> bool:
    host = str(host).lower().rstrip(".")
    if not allowlist:
        return True
    for pat in allowlist:
        pat = str(pat).lower().rstrip(".")
        if pat == "*":
            return True
        if pat.startswith("*."):
            suffix = pat[1:]          # ".example.com"
            if host == suffix[1:] or host.endswith(suffix):
                return True
        elif host == pat or fnmatch.fnmatch(host, pat):
            return True
    return False
