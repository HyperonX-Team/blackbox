//! BLACKBOX manifest: parsing, validation, normalization.
//!
//! The manifest (blackbox.yaml) is the contract between a creator and the
//! BLACKBOX runtime. Validation is strict: unknown fields and malformed
//! permissions fail loudly at pack time, not mysteriously at run time.

use crate::error::ManifestError;
use crate::platform;
use serde::Serialize;
use serde_yaml::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EntrySpec {
    pub command: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Permissions {
    pub filesystem: FilesystemPerms,
    pub network: NetworkPerms,
    pub process: ProcessPerms,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FilesystemPerms {
    pub read: Vec<String>,
    pub write: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct NetworkPerms {
    pub enabled: bool,
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ProcessPerms {
    pub spawn: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct RuntimeSpec {
    #[serde(rename = "type")]
    pub rtype: String,
    pub version: String,
    pub target: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct InterfaceSpec {
    #[serde(rename = "type")]
    pub itype: String,
    pub port: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Manifest {
    pub format_version: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub publisher: String,
    pub runtime: RuntimeSpec,
    pub entrypoint: EntrySpec,
    pub permissions: Permissions,
    pub limits: BTreeMap<String, i64>,
    pub entrypoints: BTreeMap<String, EntrySpec>,
    pub environment: EnvironmentBlock,
    pub interface: InterfaceSpec,
    pub requirements: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EnvironmentBlock {
    pub variables: BTreeMap<String, String>,
}

pub const INTERFACE_TYPES: &[&str] = &["cli", "web", "gui"];

pub fn name_valid(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 64
        && n.as_bytes()[0].is_ascii_alphanumeric()
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

pub fn version_valid(v: &str) -> bool {
    let mut parts = v.splitn(3, '.');
    let a = parts.next().unwrap_or("");
    let b = parts.next().unwrap_or("");
    let c = parts.next().unwrap_or("");
    if a.is_empty() || b.is_empty() || c.is_empty() {
        return false;
    }
    if !a.chars().all(|x| x.is_ascii_digit()) || !b.chars().all(|x| x.is_ascii_digit()) {
        return false;
    }
    let digit_part: String = c.chars().take_while(|x| x.is_ascii_digit()).collect();
    if digit_part.is_empty() {
        return false;
    }
    let tail = &c[digit_part.len()..];
    tail.chars().all(|x| x.is_ascii_alphanumeric() || x == '.' || x == '-' || x == '+')
}

fn hostname_valid(h: &str) -> bool {
    if h.is_empty() {
        return false;
    }
    let h = h.trim().to_lowercase();
    if let Some(rest) = h.strip_prefix("*.") {
        if rest.is_empty() {
            return false;
        }
        return rest
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    }
    if h == "*" {
        return true;
    }
    h.split('.').all(|part| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

fn as_str(v: &Value, where_: &str) -> Result<String, ManifestError> {
    match v.as_str() {
        Some(s) => Ok(s.to_string()),
        None => Err(ManifestError::new(format!("Manifest field '{}' must be a string.", where_))),
    }
}

fn mapping<'a>(v: &'a Value, where_: &str) -> Result<&'a serde_yaml::Mapping, ManifestError> {
    match v {
        Value::Mapping(m) => Ok(m),
        Value::Null => Err(ManifestError::new(format!("Manifest field '{}' must be a mapping, got null.", where_))),
        _ => Err(ManifestError::new(format!(
            "Manifest field '{}' must be a mapping, got {}.",
            where_,
            yaml_typename(v)
        ))),
    }
}

fn yaml_typename(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Sequence(_) => "list",
        Value::Mapping(_) => "mapping",
        Value::Tagged(_) => "tagged",
    }
}

fn strlist(v: &Value, where_: &str) -> Result<Vec<String>, ManifestError> {
    match v {
        Value::Null | Value::Bool(false) => Ok(vec![]),
        Value::String(s) if !s.is_empty() => Ok(vec![s.clone()]),
        Value::Sequence(seq) => {
            let mut out = Vec::new();
            for item in seq {
                match item.as_str() {
                    Some(s) if !s.is_empty() => out.push(s.to_string()),
                    _ => {
                        return Err(ManifestError::new(format!("Manifest field '{}' must be a list of strings.", where_)))
                    }
                }
            }
            Ok(out)
        }
        _ => Err(ManifestError::new(format!("Manifest field '{}' must be a list of strings.", where_))),
    }
}

fn validate_relpath(p: &str, where_: &str) -> Result<String, ManifestError> {
    let norm = p.replace('\\', "/");
    if !norm.starts_with("./") || norm.split('/').any(|c| c == "..") {
        return Err(ManifestError::new(format!(
            "Manifest field '{}' must be a path relative to the package root starting with './' (got '{}'). BLACKBOX packages cannot request arbitrary host paths.",
            where_, p
        )));
    }
    Ok(norm)
}

pub fn current_default_target() -> String {
    platform::current_triple()
}

pub fn load_manifest(text: &str) -> Result<Manifest, ManifestError> {
    let raw: Value = serde_yaml::from_str(text)
        .map_err(|e| ManifestError::new("blackbox.yaml is not valid YAML.").with_detail(e.to_string()))?;
    let root = match raw {
        Value::Mapping(_) => raw,
        _ => return Err(ManifestError::new("blackbox.yaml must contain a YAML mapping at the top level.")),
    };
    let map = mapping(&root, "<top>")?;

    fn req<'a>(map: &'a serde_yaml::Mapping, key: &str, where_: &str) -> Result<&'a Value, ManifestError> {
        map.get(key)
            .ok_or_else(|| ManifestError::new(format!("Manifest is missing required field '{}'.", where_)))
    }

    let fmt_ver = as_str(req(map, "format_version", "<format_version>")?, "format_version")?;
    if fmt_ver != "1" {
        return Err(ManifestError::new(format!(
            "Unsupported format_version '{}'. This build of BLACKBOX understands version '1'.",
            fmt_ver
        )));
    }

    let name = as_str(req(map, "name", "<name>")?, "name")?;
    if !name_valid(&name) {
        return Err(ManifestError::new(format!(
            "Invalid name '{}'. Use lowercase letters, digits, '.', '_' or '-'; must start alphanumeric.",
            name
        )));
    }

    let version = as_str(req(map, "version", "<version>")?, "version")?;
    if !version_valid(&version) {
        return Err(ManifestError::new(format!("Invalid version '{}'. Use semver, e.g. '0.1.0'.", version)));
    }

    let rt_value = req(map, "runtime", "runtime")?;
    let rt_map = if rt_value.is_null() {
        return Err(ManifestError::new("Manifest is missing required field 'runtime'."));
    } else {
        mapping(rt_value, "runtime")?
    };
    let rt_type = rt_map
        .get("type")
        .map(|v| as_str(v, "runtime.type"))
        .transpose()?
        .unwrap_or_default();
    let mut rt_ver = rt_map
        .get("version")
        .map(|v| as_str(v, "runtime.version"))
        .transpose()?
        .unwrap_or_default();

    const SUPPORTED: &[(&str, &str)] = &[
        ("python", "3.11"),
        ("python", "3.12"),
        ("python", "3.13"),
        ("node", "18"),
        ("node", "20"),
        ("node", "22"),
        ("node", "24"),
        ("native", "any"),
        ("native", ""),
        ("wasm", "any"),
        ("wasm", ""),
        ("rust", "any"),
        ("rust", ""),
        ("composite", "1"),
    ];
    if !SUPPORTED.iter().any(|(t, v)| *t == rt_type) {
        return Err(ManifestError::new(format!(
            "Runtime type '{}' is not supported. Supported: python, node, native, wasm, rust.",
            rt_type
        )));
    }
    if rt_type == "native" || rt_type == "wasm" || rt_type == "rust" {
        if rt_ver.is_empty() {
            rt_ver = "any".into();
        }
    } else if !SUPPORTED.iter().any(|(t, v)| *t == rt_type && *v == rt_ver) {
        return Err(ManifestError::new(format!(
            "Version '{}' is not supported for runtime '{}'. Supported: {}.",
            rt_ver,
            rt_type,
            SUPPORTED
                .iter()
                .filter(|(t, _)| *t == rt_type)
                .map(|(_, v)| *v)
                .filter(|v| !v.is_empty())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let default_target = match rt_map.get("target").map(|v| as_str(v, "runtime.target")).transpose()? {
        Some(t) => t,
        None => platform::current_triple(),
    };
    let native_or_unsupported = || {
        let _ = (rt_type.as_str(), default_target.as_str());
    };
    native_or_unsupported();

    let mut targets: Vec<String> = Vec::new();
    if let Some(Value::Sequence(seq)) = rt_map.get("targets") {
        for item in seq {
            let t = as_str(&item, "runtime.targets")?;
            if platform::target_info(&t).is_err() {
                return Err(ManifestError::new(format!("Unknown target platform '{}'.", t)));
            }
            if !targets.contains(&t) {
                targets.push(t);
            }
        }
    }
    if platform::target_info(&default_target).is_err() {
        return Err(ManifestError::new(format!(
            "Unknown target platform '{}'. Known: {}",
            default_target,
            platform::SUPPORTED_TARGETS
                .iter()
                .map(|(t, _)| *t)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let base_target = if targets.is_empty() {
        default_target
    } else {
        targets[0].clone()
    };

    let ep_value = req(map, "entrypoint", "entrypoint")?;
    let ep_map = if ep_value.is_null() {
        return Err(ManifestError::new("Manifest is missing required field 'entrypoint'."));
    } else {
        mapping(ep_value, "entrypoint")?
    };
    let ep_cmd = as_str(req(ep_map, "command", "entrypoint.command")?, "entrypoint.command")?;
    let ep_args = ep_map
        .get("args")
        .map(|v| strlist(v, "entrypoint.args"))
        .transpose()?
        .unwrap_or_default();

    match rt_type.as_str() {
        "python" => {
            if ep_cmd != "python" && ep_cmd != "python3" && ep_cmd != "py" {
                return Err(ManifestError::new(format!(
                    "Python packages must use entrypoint command 'python' (got '{}').",
                    ep_cmd
                )));
            }
        }
        "node" => {
            if ep_cmd != "node" {
                return Err(ManifestError::new(format!("Node packages must use entrypoint command 'node' (got '{}').", ep_cmd)));
            }
        }
        "wasm" => {
            if ep_cmd != "wasm" {
                return Err(ManifestError::new(format!("WASM packages must use entrypoint command 'wasm' (got '{}').", ep_cmd)));
            }
        }
        "native" | "rust" => {
            if !ep_cmd.starts_with("./") {
                return Err(ManifestError::new(format!(
                    "{:?} packages must point the entrypoint at a bundled executable, e.g. './bin/app' (got '{}').",
                    rt_type, ep_cmd
                )));
            }
        }
        _ => {}
    }

    let perms_value = map.get("permissions").cloned().unwrap_or(Value::Null);
    let perms: serde_yaml::Mapping = if perms_value.is_null() {
        serde_yaml::Mapping::new()
    } else {
        mapping(&perms_value, "permissions")?.clone()
    };
    let fs_value = perms.get("filesystem").cloned().unwrap_or(Value::Null);
    let fs = if fs_value.is_null() {
        serde_yaml::Mapping::new()
    } else {
        mapping(&fs_value, "permissions.filesystem")?.clone()
    };
    let read_paths = fs
        .get("read")
        .map(|v| strlist(v, "permissions.filesystem.read"))
        .transpose()?
        .unwrap_or_default();
    let read_paths = read_paths
        .iter()
        .map(|p| validate_relpath(p, "permissions.filesystem.read"))
        .collect::<Result<Vec<_>, _>>()?;
    let write_paths = fs
        .get("write")
        .map(|v| strlist(v, "permissions.filesystem.write"))
        .transpose()?
        .unwrap_or_default();
    let write_paths = write_paths
        .iter()
        .map(|p| validate_relpath(p, "permissions.filesystem.write"))
        .collect::<Result<Vec<_>, _>>()?;

    let net_value = perms.get("network").cloned().unwrap_or(Value::Null);
    let net = if net_value.is_null() {
        serde_yaml::Mapping::new()
    } else {
        mapping(&net_value, "permissions.network")?.clone()
    };
    let network_enabled = net.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let mut allow_hosts = Vec::new();
    for h in net.get("allow").map(|v| strlist(v, "permissions.network.allow")).transpose()?.unwrap_or_default() {
        let h = h.trim().to_lowercase();
        if h.is_empty() {
            continue;
        }
        if !hostname_valid(&h) {
            return Err(ManifestError::new(format!(
                "permissions.network.allow entry '{}' is not a hostname. Use exact hosts ('api.example.com') or wildcards ('*.example.com').",
                h
            )));
        }
        if !allow_hosts.contains(&h) {
            allow_hosts.push(h);
        }
    }

    let proc_value = perms.get("process").cloned().unwrap_or(Value::Null);
    let proc = if proc_value.is_null() {
        serde_yaml::Mapping::new()
    } else {
        mapping(&proc_value, "permissions.process")?.clone()
    };
    let spawn_enabled = proc.get("spawn").and_then(|v| v.as_bool()).unwrap_or(false);

    let mut limits = BTreeMap::new();
    let limits_value = map.get("limits").cloned().unwrap_or(Value::Null);
    if !limits_value.is_null() {
        let lm = mapping(&limits_value, "limits")?;
        if let Some(v) = lm.get("memory_mb") {
            let n = to_int(v).ok_or_else(|| ManifestError::new("limits.memory_mb must be an integer (MiB)."))?;
            if n <= 0 {
                return Err(ManifestError::new("limits.memory_mb must be a positive integer (MiB)."));
            }
            limits.insert("memory_mb".into(), n);
        }
        if let Some(v) = lm.get("cpu_percent") {
            let n = to_int(v).ok_or_else(|| ManifestError::new("limits.cpu_percent must be an integer."))?;
            if !(1..=99).contains(&n) {
                return Err(ManifestError::new("limits.cpu_percent must be between 1 and 99."));
            }
            limits.insert("cpu_percent".into(), n);
        }
        if let Some(v) = lm.get("max_processes") {
            let n = to_int(v).ok_or_else(|| ManifestError::new("limits.max_processes must be an integer."))?;
            if n <= 0 {
                return Err(ManifestError::new("limits.max_processes must be a positive integer."));
            }
            limits.insert("max_processes".into(), n);
        }
        for key in lm.keys() {
            let k = key.as_str().unwrap_or("").to_string();
            if !["memory_mb", "cpu_percent", "max_processes"].contains(&k.as_str()) {
                return Err(ManifestError::new(format!("Unknown limits key(s): {}", k)));
            }
        }
    }

    let mut entrypoints = BTreeMap::new();
    let eps_value = map.get("entrypoints").cloned().unwrap_or(Value::Null);
    if !eps_value.is_null() {
        let eps = mapping(&eps_value, "entrypoints")?;
        for (ename, spec) in eps {
            let ename = ename.as_str().unwrap_or("").to_string();
            if !entrypoint_name_valid(&ename) {
                return Err(ManifestError::new(format!("entrypoints name '{}' must be lowercase alphanumeric/./-/_ .", ename)));
            }
            let sm = mapping(spec, &format!("entrypoints.{}", ename))?;
            let ecmd = as_str(req(sm, "command", &format!("entrypoints.{}.command", ename))?, &format!("entrypoints.{}.command", ename))?;
            let eargs = sm
                .get("args")
                .map(|v| strlist(v, &format!("entrypoints.{}.args", ename)))
                .transpose()?
                .unwrap_or_default();
            match rt_type.as_str() {
                "python" => {
                    if ecmd != "python" && ecmd != "python3" && ecmd != "py" {
                        return Err(ManifestError::new(format!("entrypoints.{}: Python packages must use command 'python'.", ename)));
                    }
                }
                "node" => {
                    if ecmd != "node" {
                        return Err(ManifestError::new(format!("entrypoints.{}: Node packages must use command 'node'.", ename)));
                    }
                }
                "wasm" => {}
                "native" | "rust" => {
                    if !ecmd.starts_with("./") {
                        return Err(ManifestError::new(format!(
                            "entrypoints.{}: {:?} commands must start with './'.",
                            ename, rt_type
                        )));
                    }
                }
                _ => {}
            }
            entrypoints.insert(ename.to_string(), EntrySpec { command: ecmd, args: eargs });
        }
    }

    let mut variables = BTreeMap::new();
    let env_value = map.get("environment").cloned().unwrap_or(Value::Null);
    if !env_value.is_null() {
        let em = mapping(&env_value, "environment")?;
        if let Some(vars) = em.get("variables") {
            let vm = mapping(vars, "environment.variables")?;
            for (k, v) in vm {
                let k = k.as_str().unwrap_or("").to_string();
                if !valid_env_name_proj(&k) {
                    return Err(ManifestError::new(format!("Invalid environment variable name '{}'.", k)));
                }
                let vstr = match v {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => {
                        return Err(ManifestError::new(format!(
                            "Invalid value for environment variable '{}'.",
                            k
                        )))
                    }
                };
                variables.insert(k, vstr);
            }
        }
    }

    let iface_value = map.get("interface").cloned().unwrap_or(Value::Null);
    let iface = if iface_value.is_null() {
        serde_yaml::Mapping::new()
    } else {
        mapping(&iface_value, "interface")?.clone()
    };
    let iface_type = iface
        .get("type")
        .map(|v| as_str(v, "interface.type"))
        .transpose()?
        .unwrap_or_else(|| "cli".to_string());
    if !INTERFACE_TYPES.contains(&iface_type.as_str()) {
        return Err(ManifestError::new(format!(
            "interface.type must be one of [cli, gui, web], got '{}'.",
            iface_type
        )));
    }
    let mut iface_port = None;
    if let Some(p) = iface.get("port") {
        if !p.is_null() {
            let n = to_int(p).ok_or_else(|| ManifestError::new("interface.port must be an integer."))?;
            if n <= 0 || n >= 65536 {
                return Err(ManifestError::new("interface.port must be a valid TCP port."));
            }
            iface_port = Some(n as u64);
        }
    }

    let requirements = match map.get("requirements") {
        Some(v) if !v.is_null() => as_str(v, "requirements")?,
        _ => {
            if rt_type == "node" {
                "package.json".to_string()
            } else {
                "requirements.txt".to_string()
            }
        }
    };

    Ok(Manifest {
        format_version: "1".into(),
        name,
        version,
        description: match map.get("description").map(|v| as_str(v, "description")).transpose()? {
            Some(d) => d,
            None => String::new(),
        },
        publisher: match map.get("publisher").map(|v| as_str(v, "publisher")).transpose()? {
            Some(p) => p,
            None => "Unknown".to_string(),
        },
        runtime: RuntimeSpec {
            rtype: rt_type,
            version: rt_ver,
            target: if targets.is_empty() { base_target.clone() } else { base_target.clone() },
            targets,
        },
        entrypoint: EntrySpec { command: ep_cmd, args: ep_args },
        permissions: Permissions {
            filesystem: FilesystemPerms { read: read_paths, write: write_paths },
            network: NetworkPerms { enabled: network_enabled, allow: allow_hosts },
            process: ProcessPerms { spawn: spawn_enabled },
        },
        limits,
        entrypoints,
        environment: EnvironmentBlock { variables },
        interface: InterfaceSpec { itype: iface_type, port: iface_port },
        requirements,
    })
}

fn entrypoint_name_valid(n: &str) -> bool {
    let mut chars = n.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

fn to_int(v: &Value) -> Option<i64> {
    if let Some(n) = v.as_i64() {
        return Some(n);
    }
    if let Some(u) = v.as_u64() {
        return Some(u as i64);
    }
    if let Some(s) = v.as_str() {
        return s.trim().parse().ok();
    }
    None
}

fn valid_env_name_proj(name: &str) -> bool {
    crate::crypto::valid_env_name(name)
}

/// Human-readable summary used by `blackbox inspect`.
pub fn summarize(m: &Manifest) -> String {
    let p = &m.permissions;
    let fs_mode = if p.filesystem.read.is_empty() && p.filesystem.write.is_empty() {
        "none"
    } else {
        "restricted"
    };
    let mut lines = vec![
        format!("Name:        {}", m.name),
        format!("Version:     {}", m.version),
        format!("Publisher:   {}", m.publisher),
        format!("Description: {}", if m.description.is_empty() { "-" } else { &m.description }),
        format!(
            "Runtime:     {} {} ({})",
            m.runtime.rtype, m.runtime.version, m.runtime.target
        ),
        String::new(),
        "Entrypoint:".to_string(),
        format!(
            "  {} {}",
            m.entrypoint.command,
            m.entrypoint.args.join(" ")
        ),
        String::new(),
        "Permissions:".to_string(),
        format!("  filesystem: {}", fs_mode),
    ];
    for rp in &p.filesystem.read {
        lines.push(format!("    read:  {}", rp));
    }
    for wp in &p.filesystem.write {
        lines.push(format!("    write: {}", wp));
    }
    lines.push(format!(
        "  network: {}",
        if p.network.enabled { "enabled" } else { "disabled" }
    ));
    if !p.network.allow.is_empty() {
        lines.push(format!("    allow: {}", p.network.allow.join(", ")));
    }
    if !m.limits.is_empty() {
        let lim: Vec<String> = m.limits.iter().map(|(k, v)| format!("{}={}", k, v)).collect();
        lines.push(format!("  limits: {}", lim.join(", ")));
    }
    lines.push(format!(
        "  process spawning: {}",
        if p.process.spawn { "allowed" } else { "denied" }
    ));
    let envs: Vec<String> = m.environment.variables.keys().map(|k| format!("{}=...", k)).collect();
    lines.push(format!(
        "  environment: {}",
        if envs.is_empty() { "none".to_string() } else { envs.join(", ") }
    ));
    lines.push(format!("  interface: {}", m.interface.itype));
    if !m.entrypoints.is_empty() {
        lines.push(format!("  subcommands: {}", m.entrypoints.keys().cloned().collect::<Vec<_>>().join(", ")));
    }
    lines.join("\n")
}
