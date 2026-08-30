"""BLACKBOX manifest: parsing, validation, normalization.

The manifest (blackbox.yaml) is the contract between a creator and the
BLACKBOX runtime. Validation is strict: unknown fields and malformed
permissions fail loudly at pack time, not mysteriously at run time.
"""

import re

import yaml

from blackbox.errors import ManifestError
from blackbox.platform import SUPPORTED_TARGETS, current_triple
from blackbox.runtime.providers import PythonProvider, NodeProvider

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-+]*$")
ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
ENTRYPOINT_NAME_RE = re.compile(r"^[a-z][a-z0-9._-]{0,63}$")
HOST_RE = re.compile(r"^\*?(\.[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?|[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?)$")
RUNTIME_VERSIONS = {
    "python": set(PythonProvider.PINNED),
    "node": set(NodeProvider.SUPPORTED_MAJORS),
    "native": {"any", ""},
}
INTERFACE_TYPES = {"cli", "web", "gui"}


def _req(d, key, where):
    if not isinstance(d, dict) or key not in d:
        raise ManifestError(f"Manifest is missing required field '{where}{key}'.")
    return d[key]


def _mapping(v, where):
    if v is None:
        return {}
    if not isinstance(v, dict):
        raise ManifestError(f"Manifest field '{where}' must be a mapping, got {type(v).__name__}.")
    return v


def _strlist(v, where):
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ManifestError(f"Manifest field '{where}' must be a list of strings.")
    return v


def _validate_relpath(p, where):
    norm = p.replace("\\", "/")
    if not norm.startswith("./") or ".." in norm.split("/"):
        raise ManifestError(
            f"Manifest field '{where}' must be a path relative to the package root "
            f"starting with './' (got '{p}'). BLACKBOX packages cannot request arbitrary host paths."
        )
    return norm


def load_manifest(text: str) -> dict:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ManifestError("blackbox.yaml is not valid YAML.", detail=str(e))
    if not isinstance(raw, dict):
        raise ManifestError("blackbox.yaml must contain a YAML mapping at the top level.")

    fmt = str(_req(raw, "format_version", ""))
    if fmt != "1":
        raise ManifestError(f"Unsupported format_version '{fmt}'. This build of BLACKBOX understands version '1'.")

    name = str(_req(raw, "name", ""))
    if not NAME_RE.match(name):
        raise ManifestError(
            f"Invalid name '{name}'. Use lowercase letters, digits, '.', '_' or '-'; must start alphanumeric."
        )
    version = str(_req(raw, "version", ""))
    if not VERSION_RE.match(version):
        raise ManifestError(f"Invalid version '{version}'. Use semver, e.g. '0.1.0'.")

    rt = _mapping(_req(raw, "runtime", ""), "runtime")
    rt_type = str(rt.get("type", ""))
    rt_ver = str(rt.get("version", ""))
    if rt_type not in RUNTIME_VERSIONS:
        raise ManifestError(
            f"Runtime type '{rt_type}' is not supported. Supported: {', '.join(sorted(RUNTIME_VERSIONS))}.",
            try_hint="python, node, and native (prebuilt binaries) are first-class in the MVP. "
                     "See docs/architecture.md for adding runtimes.",
        )
    if rt_type == "native":
        rt_ver = rt_ver or "any"
    if rt_ver not in RUNTIME_VERSIONS[rt_type]:
        raise ManifestError(
            f"Version '{rt_ver}' is not supported for runtime '{rt_type}'. "
            f"Supported: {', '.join(sorted(v for v in RUNTIME_VERSIONS[rt_type] if v))}")
    target = str(rt.get("target", current_triple()))
    if target not in SUPPORTED_TARGETS:
        raise ManifestError(f"Unknown target platform '{target}'. Known: " + ", ".join(sorted(SUPPORTED_TARGETS)))

    ep = _mapping(_req(raw, "entrypoint", ""), "entrypoint")
    ep_cmd = str(_req(ep, "command", "entrypoint."))
    ep_args = _strlist(ep.get("args"), "entrypoint.args")
    if rt_type == "python" and ep_cmd not in ("python", "python3", "py"):
        raise ManifestError(f"Python packages must use entrypoint command 'python' (got '{ep_cmd}').")
    if rt_type == "node" and ep_cmd != "node":
        raise ManifestError(f"Node packages must use entrypoint command 'node' (got '{ep_cmd}').")
    if rt_type == "native" and not ep_cmd.startswith("./"):
        raise ManifestError(f"Native packages must point the entrypoint at a bundled executable, e.g. './bin/app' (got '{ep_cmd}').")

    perms = _mapping(raw.get("permissions"), "permissions")
    fs = _mapping(perms.get("filesystem"), "permissions.filesystem")
    read_paths = [_validate_relpath(p, "permissions.filesystem.read") for p in _strlist(fs.get("read"), "permissions.filesystem.read")]
    write_paths = [_validate_relpath(p, "permissions.filesystem.write") for p in _strlist(fs.get("write"), "permissions.filesystem.write")]
    net = _mapping(perms.get("network"), "permissions.network")
    network_enabled = bool(net.get("enabled", False))
    allow_hosts = []
    for h in _strlist(net.get("allow"), "permissions.network.allow"):
        h = str(h).strip().lower()
        if not HOST_RE.match(h):
            raise ManifestError(
                f"permissions.network.allow entry '{h}' is not a hostname. "
                f"Use exact hosts ('api.example.com') or wildcards ('*.example.com').")
        allow_hosts.append(h)
    process = _mapping(perms.get("process"), "permissions.process")
    spawn_enabled = bool(process.get("spawn", False))

    limits_block = _mapping(raw.get("limits"), "limits")
    limits = {}
    if "memory_mb" in limits_block:
        v = int(limits_block["memory_mb"])
        if v <= 0:
            raise ManifestError("limits.memory_mb must be a positive integer (MiB).")
        limits["memory_mb"] = v
    if "cpu_percent" in limits_block:
        v = int(limits_block["cpu_percent"])
        if not 1 <= v <= 99:
            raise ManifestError("limits.cpu_percent must be between 1 and 99.")
        limits["cpu_percent"] = v
    if "max_processes" in limits_block:
        v = int(limits_block["max_processes"])
        if v <= 0:
            raise ManifestError("limits.max_processes must be a positive integer.")
        limits["max_processes"] = v
    _unknown_limits = set(limits_block) - {"memory_mb", "cpu_percent", "max_processes"}
    if _unknown_limits:
        raise ManifestError(f"Unknown limits key(s): {', '.join(sorted(_unknown_limits))}.")

    entrypoints = {}
    for _ename, _spec in _mapping(raw.get("entrypoints"), "entrypoints").items():
        _ename = str(_ename)
        if not ENTRYPOINT_NAME_RE.match(_ename):
            raise ManifestError(f"entrypoints name '{_ename}' must be lowercase alphanumeric/./-/_ .")
        _spec = _mapping(_spec, f"entrypoints.{_ename}")
        _ecmd = str(_req(_spec, "command", f"entrypoints.{_ename}."))
        _eargs = _strlist(_spec.get("args"), f"entrypoints.{_ename}.args")
        if rt_type == "python" and _ecmd not in ("python", "python3", "py"):
            raise ManifestError(f"entrypoints.{_ename}: Python packages must use command 'python'.")
        if rt_type == "node" and _ecmd != "node":
            raise ManifestError(f"entrypoints.{_ename}: Node packages must use command 'node'.")
        if rt_type == "native" and not _ecmd.startswith("./"):
            raise ManifestError(f"entrypoints.{_ename}: native commands must start with './'.")
        entrypoints[_ename] = {"command": _ecmd, "args": _eargs}

    env_block = _mapping(raw.get("environment"), "environment")
    variables = {}
    for k, v in _mapping(env_block.get("variables"), "environment.variables").items():
        if not ENV_NAME_RE.match(str(k)):
            raise ManifestError(f"Invalid environment variable name '{k}'.")
        variables[str(k)] = str(v)

    iface = _mapping(raw.get("interface"), "interface")
    iface_type = str(iface.get("type", "cli"))
    if iface_type not in INTERFACE_TYPES:
        raise ManifestError(f"interface.type must be one of {sorted(INTERFACE_TYPES)}, got '{iface_type}'.")
    iface_port = iface.get("port")
    if iface_port is not None:
        iface_port = int(iface_port)
        if not (0 < iface_port < 65536):
            raise ManifestError("interface.port must be a valid TCP port.")

    return {
        "format_version": "1",
        "name": name,
        "version": version,
        "description": str(raw.get("description", "")),
        "publisher": str(raw.get("publisher", "Unknown")),
        "runtime": {"type": rt_type, "version": rt_ver, "target": target},
        "entrypoint": {"command": ep_cmd, "args": ep_args},
        "permissions": {
            "filesystem": {"read": read_paths, "write": write_paths},
            "network": {"enabled": network_enabled, "allow": allow_hosts},
            "process": {"spawn": spawn_enabled},
        },
        "limits": limits,
        "entrypoints": entrypoints,
        "environment": {"variables": variables},
        "interface": {"type": iface_type, "port": iface_port},
        "requirements": str(raw.get("requirements",
                                    "package.json" if rt_type == "node" else "requirements.txt")),
    }


def summarize(manifest: dict) -> str:
    """Human-readable summary used by `blackbox inspect`."""
    p = manifest["permissions"]
    fs_mode = "restricted" if (p["filesystem"]["read"] or p["filesystem"]["write"]) else "none"
    lines = [
        f"Name:        {manifest['name']}",
        f"Version:     {manifest['version']}",
        f"Publisher:   {manifest['publisher']}",
        f"Description: {manifest['description'] or '-'}",
        f"Runtime:     {manifest['runtime']['type']} {manifest['runtime']['version']} ({manifest['runtime']['target']})",
        "",
        "Entrypoint:",
        f"  {manifest['entrypoint']['command']} " + " ".join(manifest["entrypoint"]["args"]),
        "",
        "Permissions:",
        f"  filesystem: {fs_mode}",
    ]
    for rp in p["filesystem"]["read"]:
        lines.append(f"    read:  {rp}")
    for wp in p["filesystem"]["write"]:
        lines.append(f"    write: {wp}")
    lines.append(f"  network: {'enabled' if p['network']['enabled'] else 'disabled'}")
    if p["network"]["allow"]:
        lines.append(f"    allow: {', '.join(p['network']['allow'])}")
    if manifest.get("limits"):
        lim = ", ".join(f"{k}={v}" for k, v in sorted(manifest["limits"].items()))
        lines.append(f"  limits: {lim}")
    lines.append(f"  process spawning: {'allowed' if p['process']['spawn'] else 'denied'}")
    lines.append(f"  environment: {', '.join(f'{k}=...' for k in manifest['environment']['variables']) or 'none'}")
    lines.append(f"  interface: {manifest['interface']['type']}")
    if manifest.get("entrypoints"):
        lines.append(f"  subcommands: {', '.join(sorted(manifest['entrypoints']))}")
    return "\n".join(lines)
