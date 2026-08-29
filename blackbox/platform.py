"""Host platform detection and target platform descriptors."""

import platform
import sys

SUPPORTED_TARGETS = {
    "x86_64-unknown-linux-gnu": {"os": "linux", "arch": "x86_64"},
    "aarch64-unknown-linux-gnu": {"os": "linux", "arch": "aarch64"},
    "aarch64-apple-darwin": {"os": "macos", "arch": "arm64"},
    "x86_64-apple-darwin": {"os": "macos", "arch": "x86_64"},
    "x86_64-pc-windows-msvc": {"os": "windows", "arch": "x86_64"},
}


def current_triple() -> str:
    system = sys.platform
    machine = platform.machine().lower()
    if system.startswith("linux"):
        arch = "aarch64" if machine in ("aarch64", "arm64") else "x86_64"
        return f"{arch}-unknown-linux-gnu"
    if system == "darwin":
        arch = "aarch64" if machine in ("aarch64", "arm64") else "x86_64"
        return f"{arch}-apple-darwin"
    if system == "win32":
        return "x86_64-pc-windows-msvc"
    raise RuntimeError(f"Unsupported platform: {system}/{machine}")


def target_info(triple: str) -> dict:
    if triple not in SUPPORTED_TARGETS:
        raise RuntimeError(
            f"Unsupported target platform '{triple}'. Supported: {', '.join(sorted(SUPPORTED_TARGETS))}"
        )
    return SUPPORTED_TARGETS[triple]


def pip_target_flags(triple: str, python_version: str) -> list:
    """pip download/install flags to resolve wheels for a target platform+version."""
    info = target_info(triple)
    pyver = python_version.replace(".", "")
    if info["os"] == "linux":
        return [
            "--platform", "manylinux2014_" + ("x86_64" if info["arch"] == "x86_64" else "aarch64"),
            "--platform", f"linux_{info['arch']}",
            "--implementation", "cp",
            "--python-version", pyver,
            "--abi", f"cp{pyver}",
        ]
    if info["os"] == "macos":
        deployment = "12_0" if info["arch"] == "arm64" else "10_13"
        return [
            "--platform", f"macosx_{deployment}_{'arm64' if info['arch'] == 'arm64' else 'x86_64'}",
            "--implementation", "cp",
            "--python-version", pyver,
            "--abi", f"cp{pyver}",
        ]
    if info["os"] == "windows":
        return [
            "--platform", "win_amd64" if info["arch"] == "x86_64" else "win_arm64",
            "--implementation", "cp",
            "--python-version", pyver,
            "--abi", f"cp{pyver}",
        ]
    raise RuntimeError("unknown")


def exe(name: str, triple: str) -> str:
    return name + (".exe" if target_info(triple)["os"] == "windows" else "")


def os_name() -> str:
    return target_info(current_triple())["os"]
