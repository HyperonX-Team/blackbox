//! Host platform detection and target platform descriptors.

use crate::error::BlackboxError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetInfo {
    pub os: &'static str,
    pub arch: &'static str,
}

pub const SUPPORTED_TARGETS: &[(&str, TargetInfo)] = &[
    ("x86_64-unknown-linux-gnu", TargetInfo { os: "linux", arch: "x86_64" }),
    ("aarch64-unknown-linux-gnu", TargetInfo { os: "linux", arch: "aarch64" }),
    ("aarch64-apple-darwin", TargetInfo { os: "macos", arch: "arm64" }),
    ("x86_64-apple-darwin", TargetInfo { os: "macos", arch: "x86_64" }),
    ("x86_64-pc-windows-msvc", TargetInfo { os: "windows", arch: "x86_64" }),
];

pub fn target_info(triple: &str) -> Result<TargetInfo, BlackboxError> {
    SUPPORTED_TARGETS
        .iter()
        .find(|(t, _)| *t == triple)
        .map(|(_, info)| *info)
        .ok_or_else(|| {
            BlackboxError::new(format!(
                "Unsupported target platform '{}'. Supported: {}",
                triple,
                SUPPORTED_TARGETS
                    .iter()
                    .map(|(t, _)| *t)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

pub fn current_triple() -> String {
    let os_info = match std::env::consts::OS {
        "linux" => "unknown-linux-gnu",
        "macos" => "apple-darwin",
        "windows" => "pc-windows-msvc",
        _ => "unknown",
    };
    let arch_info = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => "x86_64",
    };
    let triple = format!("{}-{}", arch_info, os_info);
    if target_info(&triple).is_ok() {
        triple
    } else {
        // Unknown arch/os combination: still report something meaningful.
        format!("{}-{}", arch_info, os_info)
    }
}

#[allow(dead_code)]
pub fn os_name() -> &'static str {
    match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "macos",
        "windows" => "windows",
        _ => "unknown",
    }
}

/// pip download/install flags to resolve wheels for a target platform+version.
pub fn pip_target_flags(triple: &str, python_version: &str) -> Result<Vec<String>, BlackboxError> {
    let info = target_info(triple)?;
    let pyver = python_version.replace('.', "");
    let flags = match info.os {
        "linux" => vec![
            "--platform".into(),
            format!("manylinux2014_{}", if info.arch == "x86_64" { "x86_64" } else { "aarch64" }),
            "--platform".into(),
            format!("linux_{}", info.arch),
            "--implementation".into(),
            "cp".into(),
            "--python-version".into(),
            pyver.clone(),
            "--abi".into(),
            format!("cp{}", pyver),
        ],
        "macos" => {
            let deployment = if info.arch == "arm64" { "12_0" } else { "10_13" };
            vec![
                "--platform".into(),
                format!("macosx_{}_{}", deployment, if info.arch == "arm64" { "arm64" } else { "x86_64" }),
                "--implementation".into(),
                "cp".into(),
                "--python-version".into(),
                pyver.clone(),
                "--abi".into(),
                format!("cp{}", pyver),
            ]
        }
        "windows" => vec![
            "--platform".into(),
            if info.arch == "x86_64" { "win_amd64".into() } else { "win_arm64".into() },
            "--implementation".into(),
            "cp".into(),
            "--python-version".into(),
            pyver.clone(),
            "--abi".into(),
            format!("cp{}", pyver),
        ],
        _ => return Err(BlackboxError::new(format!("Unknown OS '{}'", info.os))),
    };
    Ok(flags)
}

pub fn exe(name: &str, triple: &str) -> Result<String, BlackboxError> {
    let info = target_info(triple)?;
    Ok(if info.os == "windows" {
        format!("{}.exe", name)
    } else {
        name.to_string()
    })
}

/// Host-usable python interpreter for running pip on the pack host.
pub fn host_has_python() -> bool {
    which("python").is_some() || which("python3").is_some()
}

#[cfg(unix)]
pub fn exec_bit_set(path: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
pub fn exec_bit_set(_path: &std::path::Path) -> bool {
    false
}

#[cfg(unix)]
pub fn set_exec_bit(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
pub fn set_exec_bit(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

pub fn which(cmd: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    let dirs: Vec<_> = std::env::split_paths(&path).collect();
    let exe = match std::env::consts::OS {
        "windows" => format!("{}.exe", cmd),
        _ => cmd.to_string(),
    };
    for d in &dirs {
        let cand = d.join(&exe);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}
