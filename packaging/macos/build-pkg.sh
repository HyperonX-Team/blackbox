#!/usr/bin/env bash
#
# Build a macOS installer (.pkg) that installs both programs into
# /usr/local/bin, which is on the default PATH.
#
#   usage: build-pkg.sh <version> <blackbox> <blackbox-gui> <out.pkg>
#
set -euo pipefail

VERSION="${1:?version required}"
CLI="${2:?blackbox binary required}"
GUI="${3:?blackbox-gui binary required}"
OUT="${4:?output .pkg required}"

[ -f "$CLI" ] || { echo "error: $CLI not found" >&2; exit 1; }
[ -f "$GUI" ] || { echo "error: $GUI not found" >&2; exit 1; }

root="$(mktemp -d)"
trap 'rm -rf "$root"' EXIT

mkdir -p "$root/usr/local/bin"
install -m 0755 "$CLI" "$root/usr/local/bin/blackbox"
install -m 0755 "$GUI" "$root/usr/local/bin/blackbox-gui"

pkgbuild \
  --root "$root" \
  --identifier dev.blackbox.runtime \
  --version "$VERSION" \
  --install-location / \
  "$OUT"

echo "built $OUT"
