# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build for the standalone `blackbox` CLI binary.

Produces a self-contained executable (one per OS/arch). The interpreter it
embeds is only for the CLI itself; BLACKBOX packages bring their own
verified runtimes at run time.

Templates and the sandbox shim are *data files* the CLI reads at run time
via paths relative to blackbox/__file__, so they are collected into the
same layout the source tree uses.

Build:  pyinstaller packaging/blackbox.spec
"""

import os

from PyInstaller.utils.hooks import collect_data_files, collect_submodules
from certifi import where as _cacert_path

# repo root = parent of this spec's directory
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(SPEC)))

datas = [
    (os.path.join(ROOT, "blackbox", "cli", "templates"),
     os.path.join("blackbox", "cli", "templates")),
    (os.path.join(ROOT, "blackbox", "sandbox", "shim"),
     os.path.join("blackbox", "sandbox", "shim")),
    (_cacert_path(), "certifi"),  # frozen pip needs an explicit CA bundle
]
# pip needs its own package data to run in-process: vendored certifi CA
# bundle, distlib script templates, etc. collect_data_files walks recursively.
datas += collect_data_files("pip")

hiddenimports = collect_submodules("blackbox")
# pip is imported lazily (only when frozen) by blackbox.dependency.resolver,
# so static analysis misses it; bundle it explicitly.
hiddenimports += collect_submodules("pip")
# The lazy `from blackbox.cli import commands` inside main._dispatch is
# invisible to Analysis, and collect_submodules can silently drop modules when
# the package is an editable install whose synthetic __path__ breaks
# pkgutil.walk_packages (newer pip/setuptools). Enumerate every lazily-loaded
# module explicitly: present = bundled; a typo here fails the build loudly.
hiddenimports += [
    "blackbox.cli.commands",
    "blackbox.runtime.runner",
    "blackbox.runtime.providers",
    "blackbox.runtime.manager",
    "blackbox.dependency.resolver",
    "blackbox.packaging.builder",
    "blackbox.packaging.reader",
    "blackbox.sandbox.policy",
    "blackbox.sandbox.jail",
    "blackbox.sandbox.limits",
    "blackbox.crypto.sealing",
    "blackbox.crypto.signing",
]

a = Analysis(
    [os.path.join(ROOT, "blackbox", "cli", "main.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "PyQt5", "PySide2"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="blackbox",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
)
