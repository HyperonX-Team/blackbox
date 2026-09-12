#!/usr/bin/env bash
#
# Build a Debian package (.deb) from a single pre-built binary.
#
#   usage: make-deb.sh <package> <version> <arch> <binary> [desktop] [icon]
#
#     package   Debian package name == installed command name (e.g. blackbox)
#     version   upstream version, e.g. 0.2.0
#     arch      Debian architecture, e.g. amd64 or arm64
#     binary    path to the compiled binary to install as /usr/bin/<package>
#     desktop   optional .desktop file (GUI package)
#     icon      optional .svg icon            (GUI package)
#
# Requires: dpkg-deb (available on Debian/Ubuntu runners).
set -euo pipefail

PKG="${1:?package name required}"
VER="${2:?version required}"
ARCH="${3:?architecture required}"
BIN="${4:?binary path required}"
DESKTOP="${5:-}"
ICON="${6:-}"

if [ ! -f "$BIN" ]; then
  echo "error: binary '$BIN' not found" >&2
  exit 1
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE/DEBIAN" "$STAGE/usr/bin"
install -m 0755 "$BIN" "$STAGE/usr/bin/$PKG"

DEPS="libc6"

if [ -n "$DESKTOP" ]; then
  mkdir -p "$STAGE/usr/share/applications"
  install -m 0644 "$DESKTOP" "$STAGE/usr/share/applications/$PKG.desktop"
  # egui/eframe runtime libraries
  DEPS="libc6, libgtk-3-0, libxkbcommon0, libgl1, libxcb1"
fi

if [ -n "$ICON" ] && [ -f "$ICON" ]; then
  mkdir -p "$STAGE/usr/share/icons/hicolor/scalable/apps"
  install -m 0644 "$ICON" "$STAGE/usr/share/icons/hicolor/scalable/apps/$PKG.svg"
fi

INSTALLED_SIZE="$(du -sk "$STAGE" | cut -f1)"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: $PKG
Version: $VER
Architecture: $ARCH
Maintainer: Kareem Harimech <kareemharimech7@gmail.com>
Installed-Size: $INSTALLED_SIZE
Depends: $DEPS
Section: utils
Priority: optional
Homepage: https://github.com/HyperonX-Team/blackbox
Description: BLACKBOX - download a machine
 BLACKBOX packs a program together with its runtime, dependencies,
 interface and permissions into a single portable, reproducible
 .blackbox file. Recipients need nothing installed: no Python, no
 Node.js, no package manager. The file is the product.
EOF

OUT="${PKG}_${VER}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "built $OUT"
