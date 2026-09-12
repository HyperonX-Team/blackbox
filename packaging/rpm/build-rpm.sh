#!/usr/bin/env bash
#
# Build an RPM containing both programs, installed into /usr/bin.
#
#   usage: build-rpm.sh <version> <arch> <blackbox> <blackbox-gui> <desktop> <icon>
#
set -euo pipefail

VERSION="${1:?version required}"
ARCH="${2:?architecture required}"
CLI="${3:?blackbox binary required}"
GUI="${4:?blackbox-gui binary required}"
DESKTOP="${5:?desktop file required}"
ICON="${6:?icon file required}"

for f in "$CLI" "$GUI" "$DESKTOP" "$ICON"; do
  [ -f "$f" ] || { echo "error: $f not found" >&2; exit 1; }
done

top="$PWD/_rpm"
rm -rf "$top"
mkdir -p "$top/BUILD" "$top/RPMS" "$top/SOURCES" "$top/SPECS" "$top/SRPMS"

cp "$CLI"     "$top/SOURCES/blackbox"
cp "$GUI"     "$top/SOURCES/blackbox-gui"
cp "$DESKTOP" "$top/SOURCES/blackbox-gui.desktop"
cp "$ICON"    "$top/SOURCES/blackbox.svg"

sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" \
  packaging/rpm/blackbox.spec > "$top/SPECS/blackbox.spec"

rpmbuild -bb --define "_topdir $top" "$top/SPECS/blackbox.spec"

find "$top/RPMS" -name '*.rpm' -exec cp {} . \;
ls -l ./*.rpm
