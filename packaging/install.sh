#!/bin/sh
#
# Blackbox installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/HyperonX-Team/blackbox/main/packaging/install.sh | sh
#
# Options (environment variables):
#   BLACKBOX_VERSION   a release tag such as v0.2.0, or "latest" (default)
#   BLACKBOX_PREFIX    install prefix (default /usr/local, or ~/.local if not writable)
#   BLACKBOX_NO_SUDO   set to 1 to never call sudo; fall back to ~/.local/bin
#
# It downloads the release archive for this machine, checks it against the
# release SHA256SUMS.txt, and installs blackbox and blackbox-gui on the PATH.

set -eu

REPO="HyperonX-Team/blackbox"
VERSION="${BLACKBOX_VERSION:-latest}"
PREFIX="${BLACKBOX_PREFIX:-}"

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v uname >/dev/null 2>&1 || die "this installer needs uname"
command -v tar   >/dev/null 2>&1 || die "this installer needs tar"

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  die "this installer needs curl or wget"
fi

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux)  os_part=linux ;;
  Darwin) os_part=macos ;;
  *) die "unsupported system: $os (use the Windows installer or build from source)" ;;
esac

case "$arch" in
  x86_64|amd64)
    [ "$os_part" = macos ] && die "no Intel macOS build is published; Apple Silicon only"
    asset="blackbox-linux-amd64.tar.gz" ;;
  aarch64|arm64)
    if [ "$os_part" = macos ]; then asset="blackbox-macos-aarch64.tar.gz"
    else asset="blackbox-linux-arm64.tar.gz"; fi ;;
  *) die "unsupported architecture: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t blackbox)
trap 'rm -rf "$tmp"' EXIT INT TERM

say "Downloading $asset"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"

# Verify against the release checksums when they are reachable.
if fetch "$base/SHA256SUMS.txt" "$tmp/SHA256SUMS.txt" 2>/dev/null; then
  line=$(grep " $asset\$" "$tmp/SHA256SUMS.txt" 2>/dev/null || true)
  if [ -n "$line" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      (cd "$tmp" && printf '%s\n' "$line" | sha256sum -c -) || die "checksum mismatch, refusing to install"
    elif command -v shasum >/dev/null 2>&1; then
      (cd "$tmp" && printf '%s\n' "$line" | shasum -a 256 -c -) || die "checksum mismatch, refusing to install"
    fi
    say "Checksum verified"
  fi
fi

tar -xzf "$tmp/$asset" -C "$tmp"
srcdir="$tmp/${asset%.tar.gz}"
[ -f "$srcdir/blackbox" ] || die "the archive did not contain the blackbox binary"

# Choose a prefix.
if [ -z "$PREFIX" ]; then
  if [ -w /usr/local ] || [ -w /usr/local/bin ] 2>/dev/null; then
    PREFIX=/usr/local
  elif [ "$(id -u 2>/dev/null || echo 1)" = "0" ]; then
    PREFIX=/usr/local
  elif [ "${BLACKBOX_NO_SUDO:-0}" = "1" ]; then
    PREFIX="$HOME/.local"
  elif command -v sudo >/dev/null 2>&1; then
    PREFIX=/usr/local
  else
    PREFIX="$HOME/.local"
  fi
fi

bindir="$PREFIX/bin"
need_sudo=no
if [ ! -d "$bindir" ] || [ ! -w "$bindir" ]; then
  if [ "$PREFIX" = "/usr/local" ] && [ "${BLACKBOX_NO_SUDO:-0}" != "1" ] && command -v sudo >/dev/null 2>&1; then
    need_sudo=yes
  fi
fi

run() { if [ "$need_sudo" = yes ]; then sudo "$@"; else "$@"; fi; }

run mkdir -p "$bindir"
run install -m 0755 "$srcdir/blackbox" "$bindir/blackbox"
if [ -f "$srcdir/blackbox-gui" ]; then
  run install -m 0755 "$srcdir/blackbox-gui" "$bindir/blackbox-gui"
fi

say ""
say "Installed to $bindir"
say "  $bindir/blackbox"
[ -f "$srcdir/blackbox-gui" ] && say "  $bindir/blackbox-gui"

case ":$PATH:" in
  *":$bindir:"*) ;;
  *) say ""
     say "Add it to your PATH:"
     say "  echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.profile" ;;
esac
