#!/bin/sh
#
# Blackbox installer for Linux and macOS.
#
#   curl -fsSL https://github.com/HyperonX-Team/blackbox/releases/latest/download/install.sh | sh
#
# Options (environment variables):
#   BLACKBOX_VERSION   a release tag such as v0.2.0, or "latest" (default)
#   BLACKBOX_PREFIX    install prefix (default /usr/local, or ~/.local if not writable)
#   BLACKBOX_NO_SUDO   set to 1 to never call sudo; fall back to ~/.local/bin
#   NO_COLOR           set to anything to disable colour
#
# It downloads the release archive for this machine, checks it against the
# release SHA256SUMS.txt, and installs blackbox and blackbox-gui on the PATH.

set -eu

REPO="HyperonX-Team/blackbox"
VERSION="${BLACKBOX_VERSION:-latest}"
PREFIX="${BLACKBOX_PREFIX:-}"

# ------------------------------------------------------------------ output
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != "dumb" ]; then
  YEL=$(printf '\033[38;5;220m')
  GRN=$(printf '\033[38;5;35m')
  DIM=$(printf '\033[2m')
  BLD=$(printf '\033[1m')
  RST=$(printf '\033[0m')
else
  YEL= GRN= DIM= BLD= RST=
fi

banner() {
  printf '\n'
  printf '%s' "$YEL"
  cat <<'ART'
   ██████╗ ██╗      █████╗  ██████╗██╗  ██╗██████╗  ██████╗ ██╗  ██╗
  ██╔══██╗██║     ██╔══██╗██╔════╝██║ ██╔╝██╔══██╗██╔═══██╗╚██╗██╔╝
  ██████╔╝██║     ███████║██║     █████╔╝ ██████╔╝██║   ██║ ╚███╔╝
  ██╔══██╗██║     ██╔══██║██║     ██╔═██╗ ██╔══██╗██║   ██║ ██╔██╗
  ██████╔╝███████╗██║  ██║╚██████╗██║  ██╗██████╔╝╚██████╔╝██╔╝ ██╗
  ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝
ART
  printf '%s' "$RST"
}

rule() {
  i=0; line="  "
  while [ "$i" -lt 64 ]; do line="$line─"; i=$((i + 1)); done
  printf '%s%s%s\n' "$DIM" "$line" "$RST"
}

field() {
  printf '  %s%-10s%s %s\n' "$DIM" "$1" "$RST" "$2"
}

step() {
  printf '  %s[%s/%s]%s %s\n' "$DIM" "$1" "$2" "$RST" "$3"
}

ok() {
  printf '        %s%s%s\n' "$GRN" "$1" "$RST"
}

die() {
  printf '\n  %serror%s %s\n\n' "$YEL" "$RST" "$*" >&2
  exit 1
}

# ------------------------------------------------------------------ checks
command -v uname >/dev/null 2>&1 || die "this installer needs uname"
command -v tar   >/dev/null 2>&1 || die "this installer needs tar"

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
else
  die "this installer needs curl or wget"
fi

# ------------------------------------------------------------------ target
os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux)  os_part=linux ;;
  Darwin) os_part=macos ;;
  *) die "unsupported system: $os" ;;
esac

case "$arch" in
  x86_64|amd64)
    [ "$os_part" = macos ] && die "no Intel macOS build is published; Apple silicon only"
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

banner
rule
printf '  %sinstall a machine%s\n\n' "$BLD" "$RST"
field "platform" "$os_part $arch"
field "release"  "$VERSION"
field "archive"  "$asset"
printf '\n'

# ------------------------------------------------------------------ work
tmp=$(mktemp -d 2>/dev/null || mktemp -d -t blackbox)
trap 'rm -rf "$tmp"' EXIT INT TERM

step 1 3 "downloading $asset"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
ok "$(wc -c < "$tmp/$asset" | tr -d ' ') bytes"

step 2 3 "verifying checksum"
if fetch "$base/SHA256SUMS.txt" "$tmp/SHA256SUMS.txt" 2>/dev/null; then
  line=$(grep " $asset\$" "$tmp/SHA256SUMS.txt" 2>/dev/null || true)
  if [ -n "$line" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
      (cd "$tmp" && printf '%s\n' "$line" | sha256sum -c - >/dev/null 2>&1) || die "checksum mismatch, refusing to install"
    elif command -v shasum >/dev/null 2>&1; then
      (cd "$tmp" && printf '%s\n' "$line" | shasum -a 256 -c - >/dev/null 2>&1) || die "checksum mismatch, refusing to install"
    else
      ok "no sha256 tool available, skipping"
    fi
    ok "matches SHA256SUMS.txt"
  else
    ok "no entry for this archive, skipping"
  fi
else
  ok "checksums not reachable, skipping"
fi

tar -xzf "$tmp/$asset" -C "$tmp"
srcdir="$tmp/${asset%.tar.gz}"
[ -f "$srcdir/blackbox" ] || die "the archive did not contain the blackbox binary"

# choose a prefix
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

step 3 3 "installing to $bindir"
run mkdir -p "$bindir"
run install -m 0755 "$srcdir/blackbox" "$bindir/blackbox"
if [ -f "$srcdir/blackbox-gui" ]; then
  run install -m 0755 "$srcdir/blackbox-gui" "$bindir/blackbox-gui"
fi
ok "done"

# ------------------------------------------------------------------ summary
printf '\n'
rule
printf '  %sinstalled%s\n\n' "$BLD" "$RST"
printf '  %s%-14s%s %s\n' "$DIM" "blackbox" "$RST" "$bindir/blackbox"
if [ -f "$srcdir/blackbox-gui" ]; then
  printf '  %s%-14s%s %s\n' "$DIM" "blackbox-gui" "$RST" "$bindir/blackbox-gui"
fi

case ":$PATH:" in
  *":$bindir:"*)
    printf '\n  %stry it%s\n\n' "$BLD" "$RST"
    printf '  blackbox doctor\n\n' ;;
  *)
    printf '\n  %sadd it to your PATH%s\n\n' "$BLD" "$RST"
    printf "  echo 'export PATH=\"%s:\$PATH\"' >> ~/.profile\n" "$bindir"
    printf '\n  %sthen%s\n\n' "$BLD" "$RST"
    printf '  blackbox doctor\n\n' ;;
esac
