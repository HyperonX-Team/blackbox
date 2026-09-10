//! Runtime providers: the extension point for every language BLACKBOX
//! supports. A provider provisions an interpreter (hash-verified), locks
//! dependencies at pack time when applicable, and shapes the execution
//! environment for `blackbox run`.
//!
//! Providers: python, node, native (MVP) + NEW: wasm, rust.

use crate::error::{BlackboxError, RuntimeMissingError};
use crate::manifest::Manifest;
use crate::storage::ensure_home;
use crate::{deterministic as det, platform};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

pub trait RuntimeProvider: Sync + Send {
    fn rtype(&self) -> &'static str;
    fn ensure(
        &self,
        version: &str,
        target: &str,
        pin: Option<&Value>,
    ) -> Result<Option<PathBuf>, BlackboxError>;
    fn env(
        &self,
        exe: Option<&Path>,
        site_dir: &Path,
        app_dir: &Path,
        target: &str,
    ) -> BTreeMap<String, String>;
    fn resolve_command(
        &self,
        command: &str,
        args: &[String],
        exe: Option<&Path>,
        app_dir: &Path,
        manifest: &Manifest,
    ) -> Result<Vec<String>, BlackboxError>;
}

fn check_target(target: &str) -> Result<(), BlackboxError> {
    let here = platform::current_triple();
    let a = platform::target_info(&here)?;
    let b = platform::target_info(target)?;
    if a.os != b.os || a.arch != b.arch {
        return Err(RuntimeMissingError::new(format!(
            "This package targets {}, but this machine is {}.",
            target, here
        ))
        .with_try("BLACKBOX cannot execute foreign-architecture binaries. Run on a matching machine.")
        .into());
    }
    Ok(())
}

// ----------------------------------------------------------- helpers

pub fn http_download(url: &str, timeout_secs: u64) -> Result<Vec<u8>, BlackboxError> {
    crate::serve::http_get_with_timeout(url, timeout_secs).map_err(|e| {
        BlackboxError::new(format!("Could not download {}", url)).with_detail(format!("{}", e))
    })
}

/// Extract a tar.gz (python-build-standalone) or tar.xz (wasmtime/rust dist)
/// into dest with traversal checks, then atomically rename into place.
fn extract_archive_bytes(
    blob: &[u8],
    mode: ArchiveKind,
    dest: &Path,
    exe_names: &[&str],
) -> Result<Option<PathBuf>, BlackboxError> {
    let staged = dest.with_extension("staging");
    let _ = std::fs::remove_dir_all(&staged);
    std::fs::create_dir_all(&staged)
        .map_err(|e| BlackboxError::new("Could not create runtime staging dir").with_detail(e.to_string()))?;
    let files = match mode {
        ArchiveKind::TarGz => tar_gz_extract(blob)?,
        ArchiveKind::TarXz => tar_xz_extract(blob)?,
        ArchiveKind::Zip => zip_extract(blob)?,
    };
    let mut found_exe: Option<PathBuf> = None;
    for (name, data) in &files {
        let norm = name.replace('\\', "/");
        for comp in norm.split('/') {
            if comp == ".." {
                return Err(RuntimeMissingError::new("Runtime archive contains an unsafe path.").with_detail(norm.clone()).into());
            }
        }
        if Path::new(&norm).is_absolute() {
            return Err(RuntimeMissingError::new("Runtime archive contains an unsafe path.").with_detail(norm).into());
        }
        let target = staged.join(&norm);
        if norm.ends_with('/') {
            std::fs::create_dir_all(&target)
                .map_err(|e| BlackboxError::new("Runtime extraction failed").with_detail(e.to_string()))?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BlackboxError::new("Runtime extraction failed").with_detail(e.to_string()))?;
        }
        std::fs::write(&target, data)
            .map_err(|e| BlackboxError::new("Runtime extraction failed").with_detail(e.to_string()))?;
        let base = name.rsplit('/').next().unwrap_or("");
        if exe_names.contains(&base) {
            let _ = platform::set_exec_bit(&target);
            found_exe = Some(target.clone());
        }
    }
    if dest.exists() {
        std::fs::remove_dir_all(dest)
            .map_err(|e| BlackboxError::new("Could not replace existing runtime dir").with_detail(e.to_string()))?;
    }
    std::fs::rename(&staged, dest)
        .map_err(|e| BlackboxError::new("Could not finalize runtime dir").with_detail(e.to_string()))?;
    Ok(found_exe)
}

#[derive(Clone, Copy, PartialEq)]
enum ArchiveKind {
    TarGz,
    TarXz,
    Zip,
}

fn tar_gz_extract(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>, BlackboxError> {
    let mut gz = flate_decode(blob)?;
    let mut out = Vec::new();
    let mut archive = tar::Archive::new(Cursor::new(std::mem::take(&mut gz)));
    for entry in archive.entries().map_err(|e| BlackboxError::new("Bad runtime tar").with_detail(e.to_string()))? {
        let entry = entry.map_err(|e| BlackboxError::new("Runtime tar stream READ err").with_detail(e.to_string()))?;
        let name = entry.path().map_err(|e| BlackboxError::new("Runtime tar has bad path").with_detail(e.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        let is_dir = entry.header().entry_type().is_dir();
        let mut data = Vec::new();
        if !is_dir {
            let size = entry.header().size().unwrap_or(0);
            entry
                .take(size)
                .read_to_end(&mut data)
                .map_err(|e| BlackboxError::new("Runtime tar member unreadable").with_detail(e.to_string()))?;
        }
        let rec = (name.clone(), data);
        let _ = is_dir;
        out.push(rec);
    }
    Ok(out)
}

fn flate_decode(data: &[u8]) -> Result<Vec<u8>, BlackboxError> {
    let mut out = Vec::new();
    let mut decoder = flate2::read::GzDecoder::new(Cursor::new(data));
    decoder.read_to_end(&mut out).map_err(|e| BlackboxError::new("Could not decompress runtime archive").with_detail(e.to_string()))?;
    Ok(out)
}

fn tar_xz_extract(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>, BlackboxError> {
    let mut decoded = Vec::new();
    {
        let mut dec = xz2::read::XzDecoder::new(Cursor::new(blob));
        dec.read_to_end(&mut decoded)
            .map_err(|e| BlackboxError::new("Could not decompress .tar.xz runtime").with_detail(e.to_string()))?;
    }
    tar_gz_extract(&decoded)
}

fn zip_extract(blob: &[u8]) -> Result<Vec<(String, Vec<u8>)>, BlackboxError> {
    let mut archive = zip::ZipArchive::new(Cursor::new(blob))
        .map_err(|e| BlackboxError::new("Runtime .zip is unreadable").with_detail(e.to_string()))?;
    let mut out = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| BlackboxError::new("Runtime .zip member unreadable").with_detail(e.to_string()))?;
        let name = entry.name().replace('\\', "/");
        let mut data = Vec::new();
        if !entry.is_dir() {
            entry
                .read_to_end(&mut data)
                .map_err(|e| BlackboxError::new("Runtime .zip member unreadable").with_detail(e.to_string()))?;
        }
        out.push((name, data));
    }
    Ok(out)
}

fn run_dir(kind: &str, version: &str, target: &str) -> PathBuf {
    ensure_home().runtimes.join(kind).join(version).join(target)
}

// ---------------------------------------------------------------- python

pub const PBS_BASE: &str =
    "https://github.com/astral-sh/python-build-standalone/releases/download";
pub const PINNED_PYTHON: &[(&str, &str, &str)] = &[
    ("3.11", "3.11.10", "20241002"),
    ("3.12", "3.12.7", "20241002"),
    ("3.13", "3.13.0", "20241002"),
];

pub struct PythonProvider;

impl PythonProvider {
    fn pinned(family: &str) -> Option<(&str, &str)> {
        PINNED_PYTHON
            .iter()
            .find(|(f, _, _)| *f == family)
            .map(|(_, full, tag)| (*full, *tag))
    }
    fn executable(version: &str, target: &str) -> PathBuf {
        let root = run_dir("python", version, target);
        if platform::target_info(target).map(|i| i.os == "windows").unwrap_or(false) {
            root.join("python").join("python.exe")
        } else {
            root.join("python").join("bin").join("python3")
        }
    }
    pub fn is_installed(version: &str, target: &str) -> bool {
        Self::executable(version, target).is_file()
    }
}

impl RuntimeProvider for PythonProvider {
    fn rtype(&self) -> &'static str {
        "python"
    }
    fn ensure(
        &self,
        version: &str,
        target: &str,
        _pin: Option<&Value>,
    ) -> Result<Option<PathBuf>, BlackboxError> {
        check_target(target)?;
        let Some((full, tag)) = Self::pinned(version) else {
            return Err(RuntimeMissingError::new(format!("No pinned runtime for Python {}.", version))
                .with_try("Supported: 3.11, 3.12, 3.13")
                .into());
        };
        let exe_path = Self::executable(version, target);
        if exe_path.is_file() {
            return Ok(Some(exe_path));
        }
        let asset = format!("cpython-{}+{}-{}-install_only.tar.gz", full, tag, target);
        let url = format!("{}/{}/{}", PBS_BASE, tag, asset);
        println!("BLACKBOX: provisioning Python {} runtime (first use only, ~25 MB)...", full);
        let expected_url = format!("{}.sha256", url);
        let expected = match http_download(&expected_url, 30) {
            Ok(text) => String::from_utf8_lossy(&text).split_whitespace().next().unwrap_or("").to_string(),
            Err(_) => String::new(),
        };
        let data = http_download(&url, 600).map_err(|e| {
            RuntimeMissingError::new(format!(
                "Package requires Python {} runtime, but it is not cached and could not be downloaded.",
                version
            ))
            .with_detail(format!("Error: {} ", e))
            .with_try("Check your network connection and retry.\nOr seed offline: blackbox runtime import <tarball>\nblackbox doctor")
        })?;
        if !expected.is_empty() && det::sha256_bytes(&data) != expected {
            return Err(RuntimeMissingError::new("Downloaded Python runtime failed integrity verification.")
                .with_detail(format!("expected {}", expected))
                .with_try("Refusing to install. Retry, or run 'blackbox doctor'.")
                .into());
        }
        let exe = extract_archive_bytes(&data, ArchiveKind::TarGz, &run_dir("python", version, target), &["python3", "python.exe"])?;
        let Some(exe) = exe else {
            return Err(RuntimeMissingError::new("Runtime extraction completed but the interpreter is missing.").into());
        };
        Ok(Some(exe))
    }
    fn env(&self, _exe: Option<&Path>, site_dir: &Path, app_dir: &Path, _target: &str) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("PYTHONNOUSERSITE".into(), "1".into());
        env.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
        if !site_dir.as_os_str().is_empty() {
            let sep = if cfg!(windows) { ';' } else { ':' };
            env.insert(
                "PYTHONPATH".into(),
                format!("{}{}{}", site_dir.display(), sep, app_dir.display()),
            );
        }
        env
    }
    fn resolve_command(
        &self,
        command: &str,
        args: &[String],
        exe: Option<&Path>,
        app_dir: &Path,
        _manifest: &Manifest,
    ) -> Result<Vec<String>, BlackboxError> {
        if !["python", "python3", "py"].contains(&command) {
            return Err(BlackboxError::new(format!(
                "Python packages must use entrypoint command 'python' (got '{}').",
                command
            )));
        }
        let exe = exe.ok_or_else(|| BlackboxError::new("Python runtime executable is missing."))?;
        let mut argv = vec![exe.display().to_string(), "-u".into()];
        if let Some(first) = args.first() {
            if !first.contains('/') && !first.contains('\\') && !first.starts_with('-') {
                let cand = app_dir.join(first);
                if cand.is_file() {
                    argv.push(cand.display().to_string());
                } else {
                    argv.push(first.clone());
                }
            } else {
                argv.push(first.clone());
            }
        }
        for a in &args[1..] {
            argv.push(a.clone());
        }
        Ok(argv)
    }
}

// ------------------------------------------------------------------ node

pub const NODE_INDEX: &str = "https://nodejs.org/dist/index.json";
pub const NODE_DIST: &str = "https://nodejs.org/dist";
pub const NODE_MAJORS: &[&str] = &["18", "20", "22", "24"];

pub struct NodeProvider;

fn strip_archive_ext(asset: &str) -> String {
    let a = asset.strip_suffix(".tar.gz").or_else(|| asset.strip_suffix(".tar.xz")).or_else(|| asset.strip_suffix(".zip"));
    a.unwrap_or(asset).to_string()
}

impl NodeProvider {
    fn _dir(version: &str, target: &str) -> PathBuf {
        run_dir("node", version, target)
    }
    fn dist_basename(target: &str) -> (String, bool) {
        // returns (basename template WITH extension, is_zip)
        let info = platform::target_info(target).unwrap();
        let is_zip = info.os == "windows";
        let ext = if is_zip { ".zip" } else { ".tar.gz" };
        let file_name = format!("node-{{ver}}-{}-{}{}", dist_os(info.os), dist_arch(info.arch), ext);
        (file_name, is_zip)
    }
    fn exe_path(verdir: &Path, target: &str) -> PathBuf {
        if platform::target_info(target).map(|i| i.os == "windows").unwrap_or(false) {
            verdir.join("node.exe")
        } else {
            verdir.join("bin").join("node")
        }
    }
    pub fn is_installed(version: &str, target: &str) -> bool {
        let root = Self::_dir(version, target);
        if !root.is_dir() {
            return false;
        }
        if let Ok(entries) = std::fs::read_dir(&root) {
            for e in entries.flatten() {
                let inner = e.path();
                if Self::exe_path(&inner, target).is_file() {
                    return true;
                }
            }
        }
        false
    }
}

fn dist_os(os: &str) -> &str {
    match os {
        "windows" => "win",
        "macos" => "darwin",
        _ => "linux",
    }
}

fn dist_arch(arch: &str) -> &str {
    match arch {
        "arm64" | "aarch64" => "arm64",
        _ => "x64",
    }
}

pub fn node_pin_for_lock(version: &str, target: &str) -> Result<BTreeMap<String, String>, BlackboxError> {
    if !NODE_MAJORS.contains(&version) {
        return Err(BlackboxError::new(format!("Node major version '{}' is not supported. Supported: {}", version, NODE_MAJORS.join(", "))));
    }
    let index_text = String::from_utf8_lossy(&http_download(NODE_INDEX, 60)?).to_string();
    let index: Value = serde_json::from_str(&index_text)
        .map_err(|e| BlackboxError::new("Could not read nodejs.org distribution index.").with_detail(e.to_string()))?;
    let Some(items) = index.as_array() else {
        return Err(BlackboxError::new("Unreadable nodejs.org index."));
    };
    let entry = items.iter().find(|e| {
        e.get("version").and_then(|v| v.as_str())
            .map(|v| v.trim_start_matches('v').split('.').next().unwrap_or("") == version)
            .unwrap_or(false)
            && e.get("lts").map(|l| !l.is_null() && l != &Value::Bool(false)).unwrap_or(false)
    });
    let entry = entry.ok_or_else(|| BlackboxError::new(format!("No LTS release line found for Node {}.", version)))?;
    let exact = entry.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let (base, _is_zip) = NodeProvider::dist_basename(target);
    let asset = base.replace("{ver}", &exact);
    let shasums = String::from_utf8_lossy(&http_download(&format!("{}/{}/SHASUMS256.txt", NODE_DIST, exact), 60)?).to_string();
    let sha = shasums
        .lines()
        .find_map(|ln| {
            let mut parts = ln.split_whitespace();
            let hash = parts.next()?;
            let fname = parts.next_back()?;
            if fname == asset {
                Some(hash.to_string())
            } else {
                None
            }
        })
        .ok_or_else(|| BlackboxError::new(format!("SHASUMS256.txt has no entry for '{}'.", asset)))?;
    let mut out = BTreeMap::new();
    out.insert("version".into(), exact.trim_start_matches('v').to_string());
    out.insert("asset".into(), asset.clone());
    out.insert("url".into(), format!("{}/{}/{}", NODE_DIST, exact, asset));
    out.insert("sha256".into(), sha);
    Ok(out)
}

/// Host-side node executable usable for `npm install` at pack time.
pub fn ensure_node_for_lock(version: &str) -> Result<PathBuf, BlackboxError> {
    let target = platform::current_triple();
    let exe = NodeProvider.ensure(version, &target, None)?;
    exe.ok_or_else(|| BlackboxError::new("Node runtime executable could not be provisioned."))
}

impl RuntimeProvider for NodeProvider {
    fn rtype(&self) -> &'static str {
        "node"
    }
    fn ensure(&self, version: &str, target: &str, pin: Option<&Value>) -> Result<Option<PathBuf>, BlackboxError> {
        check_target(target)?;
        let pin = match pin {
            Some(v) if !v.is_null() => v.clone(),
            _ => serde_json::to_value(node_pin_for_lock(version, target).unwrap_or_default()).unwrap_or(Value::Null).clone(),
        };
        let pin = if pin.is_null() {
            let resolved = node_pin_for_lock(version, target)?;
            serde_json::to_value(resolved).map_err(|e| BlackboxError::new("Could not serialize node pin").with_detail(e.to_string()))?
        } else {
            pin
        };
        let asset = pin.get("asset").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let inner = strip_archive_ext(&asset);
        let root = run_dir("node", version, target);
        let verdir = root.join(&inner);
        let exe = NodeProvider::exe_path(&verdir, target);
        if exe.is_file() {
            return Ok(Some(exe));
        }
        let url = pin.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let sha = pin.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let flow_ver = pin.get("version").and_then(|v| v.as_str()).unwrap_or(version);
        println!("BLACKBOX: provisioning Node.js {} runtime (first use only, ~25 MB)...", flow_ver);
        let data = http_download(&url, 600).map_err(|e| {
            RuntimeMissingError::new(format!("Package requires Node.js {}, but it is not cached and could not be downloaded.", version))
                .with_detail(format!("Error: {}", e))
                .with_try("Retry with network, or run: blackbox doctor")
        })?;
        if !sha.is_empty() && det::sha256_bytes(&data) != sha {
            return Err(RuntimeMissingError::new("Downloaded Node runtime failed integrity verification.")
                .with_detail(format!("expected {}", sha))
                .with_try("Refusing to install. The upstream artifact changed?")
                .into());
        }
        let _ = std::fs::create_dir_all(&root);
        let kind = if asset.ends_with(".zip") { ArchiveKind::Zip } else { ArchiveKind::TarGz };
        let found = extract_archive_bytes(&data, kind, &root, &["node", "node.exe"])?;
        let resolved = found.or_else(|| NodeProvider::exe_path(&root.join(&inner), target).is_file().then(|| NodeProvider::exe_path(&root.join(&inner), target)));
        let Some(exe) = resolved else {
            return Err(RuntimeMissingError::new("Node extraction completed but the interpreter is missing.").into());
        };
        Ok(Some(exe))
    }
    fn env(&self, _exe: Option<&Path>, site_dir: &Path, _app_dir: &Path, _target: &str) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        if !site_dir.as_os_str().is_empty() {
            env.insert("NODE_PATH".into(), site_dir.join("node_modules").display().to_string());
        }
        env
    }
    fn resolve_command(
        &self,
        command: &str,
        args: &[String],
        exe: Option<&Path>,
        app_dir: &Path,
        _manifest: &Manifest,
    ) -> Result<Vec<String>, BlackboxError> {
        if command != "node" {
            return Err(BlackboxError::new(format!("Node packages must use entrypoint command 'node' (got '{}').", command)));
        }
        let exe = exe.ok_or_else(|| BlackboxError::new("Node runtime executable is missing."))?;
        let mut argv = vec![exe.display().to_string()];
        if let Some(first) = args.first() {
            let cand = app_dir.join(first);
            if cand.is_file() {
                argv.push(cand.display().to_string());
            } else {
                argv.push(first.clone());
            }
        }
        for a in &args[1..] {
            argv.push(a.clone());
        }
        Ok(argv)
    }
}

// ---------------------------------------------------------------- native

pub struct NativeProvider;

impl RuntimeProvider for NativeProvider {
    fn rtype(&self) -> &'static str {
        "native"
    }
    fn ensure(&self, _version: &str, target: &str, _pin: Option<&Value>) -> Result<Option<PathBuf>, BlackboxError> {
        check_target(target)?;
        Ok(None)
    }
    fn env(&self, _exe: Option<&Path>, _site_dir: &Path, _app_dir: &Path, _target: &str) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    fn resolve_command(
        &self,
        command: &str,
        args: &[String],
        _exe: Option<&Path>,
        app_dir: &Path,
        _manifest: &Manifest,
    ) -> Result<Vec<String>, BlackboxError> {
        if !command.starts_with("./") {
            return Err(BlackboxError::new(
                "Native packages must point the entrypoint at a bundled executable, e.g. command: ./bin/app",
            )
            .with_detail(format!("Got command: {}", command)));
        }
        let mut cand = app_dir.join(&command[2..]);
        if !cand.is_file() && cfg!(windows) {
            cand = app_dir.join(format!("{}.exe", &command[2..]));
        }
        if !cand.is_file() {
            return Err(BlackboxError::new(format!("Native entrypoint '{}' was not found in the application layer.", command))
                .with_try("Compile the binary for this target and re-pack (binaries are platform-specific)."));
        }
        let _ = platform::set_exec_bit(&cand);
        let mut argv = vec![cand.display().to_string()];
        argv.extend(args.iter().cloned());
        Ok(argv)
    }
}

// ------------------------------------------------------------------ WASM

/// NEW runtime: wasmtime CLI bundled as the interpreter. Version = wasmtime
/// release, e.g. "24.0.0". Pin resolved from the GitHub release API at pack
/// time (asset digest), verified at run time.
pub struct WasmProvider;

impl WasmProvider {
    pub fn wasmtriple(target: &str) -> &str {
        let info = platform::target_info(target).unwrap_or(platform::TargetInfo { os: "linux", arch: "x86_64" });
        match (info.os, info.arch) {
            ("linux", "aarch64") => "aarch64-linux",
            ("linux", _) => "x86_64-linux",
            ("macos", "arm64") => "aarch64-macos",
            ("macos", _) => "x86_64-macos",
            ("windows", _) => "x86_64-windows",
            _ => "x86_64-linux",
        }
    }
    fn exe(verdir: &Path, target: &str) -> PathBuf {
        if platform::target_info(target).map(|i| i.os == "windows").unwrap_or(false) {
            verdir.join("wasmtime.exe")
        } else {
            verdir.join("wasmtime")
        }
    }
    pub fn is_installed(version: &str, target: &str) -> bool {
        let root = run_dir("wasm", version, target);
        if !root.is_dir() {
            return false;
        }
        if let Ok(entries) = std::fs::read_dir(&root) {
            for e in entries.flatten() {
                if Self::exe(&e.path(), target).is_file() {
                    return true;
                }
            }
        }
        false
    }
}

pub fn wasm_pin_for_lock(version: &str, target: &str) -> Result<BTreeMap<String, String>, BlackboxError> {
    let api = format!("https://api.github.com/repos/bytecodealliance/wasmtime/releases/tags/v{}", version);
    let body = http_download(&api, 60)
        .map_err(|_| BlackboxError::new(format!("Could not resolve wasmtime v{} release metadata.", version))
            .with_try("BLACKBOX resolves wasmtime pins from the GitHub release API at pack time."))?;
    let json: Value = serde_json::from_slice(&body)
        .map_err(|e| BlackboxError::new("Could not parse wasmtime release metadata.").with_detail(e.to_string()))?;
    let wt = WasmProvider::wasmtriple(target);
    let want_parts = [format!("wasmtime-v{}-{}.tar.xz", version, wt), format!("wasmtime-v{}-{}.zip", version, wt)];
    let assets = json.get("assets").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let chosen = assets
        .iter()
        .find(|a| a.get("name").and_then(|n| n.as_str()).map(|n| want_parts.iter().any(|w| w == n)).unwrap_or(false));
    let asset_name = chosen
        .and_then(|a| a.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
        .or_else(|| want_parts.first().cloned())
        .ok_or_else(|| BlackboxError::new("Wasmtime release has no matching asset."))?;
    let url = format!(
        "https://github.com/bytecodealliance/wasmtime/releases/download/v{}/{}",
        version, asset_name
    );
    let sha = chosen
        .and_then(|a| a.get("digest").and_then(|d| d.as_str()))
        .map(|d| d.trim_start_matches("sha256:").to_string())
        .unwrap_or_default();
    let mut out = BTreeMap::new();
    out.insert("version".into(), version.to_string());
    out.insert("asset".into(), asset_name.clone());
    out.insert("url".into(), url);
    out.insert("sha256".into(), sha);
    out.insert("dist_triple".into(), wt.to_string());
    Ok(out)
}

impl RuntimeProvider for WasmProvider {
    fn rtype(&self) -> &'static str {
        "wasm"
    }
    fn ensure(&self, version: &str, target: &str, pin: Option<&Value>) -> Result<Option<PathBuf>, BlackboxError> {
        check_target(target)?;
        let pin = pin.cloned().unwrap_or_else(|| serde_json::to_value(wasm_pin_for_lock(version, target).unwrap_or_default()).unwrap_or(Value::Null));
        if pin.is_null() {
            return Err(RuntimeMissingError::new("wasm pin unknown.").into());
        }
        let wind = pin.get("asset").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let inner = strip_archive_ext(&wind);
        let root = run_dir("wasm", version, target);
        let verdir = root.join(&inner);
        let exe = WasmProvider::exe(&verdir, target);
        if exe.is_file() {
            return Ok(Some(exe));
        }
        let url = pin.get("url").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let sha = pin.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
        println!("BLACKBOX: provisioning wasmtime {} runtime (first use only, ~20 MB)...", version);
        let data = http_download(&url, 600).map_err(|e| {
            RuntimeMissingError::new(format!("Package requires wasmtime {}, but it is not cached and could not be downloaded.", version))
                .with_detail(format!("Error: {}", e))
                .with_try("Retry with network, or run: blackbox doctor")
        })?;
        if !sha.is_empty() && det::sha256_bytes(&data) != sha {
            return Err(RuntimeMissingError::new("Downloaded wasmtime runtime failed integrity verification.")
                .with_detail(format!("expected {}", sha))
                .with_try("Refusing to install.")
                .into());
        }
        let _ = std::fs::create_dir_all(&root);
        let kind = if wind.ends_with(".zip") { ArchiveKind::Zip } else { ArchiveKind::TarXz };
        let found = extract_archive_bytes(&data, kind, &root, &["wasmtime", "wasmtime.exe"])?;
        let resolved = found.or_else(|| WasmProvider::exe(&root.join(&inner), target).is_file().then(|| WasmProvider::exe(&root.join(&inner), target)));
        let Some(exe) = resolved else {
            return Err(RuntimeMissingError::new("wasmtime extraction completed but the runtime is missing.").into());
        };
        Ok(Some(exe))
    }
    fn env(&self, _exe: Option<&Path>, _site_dir: &Path, _app_dir: &Path, _target: &str) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    fn resolve_command(
        &self,
        command: &str,
        args: &[String],
        exe: Option<&Path>,
        app_dir: &Path,
        manifest: &Manifest,
    ) -> Result<Vec<String>, BlackboxError> {
        if command != "wasm" {
            return Err(BlackboxError::new(format!("WASM packages must use entrypoint command 'wasm' (got '{}').", command)));
        }
        let exe = exe.ok_or_else(|| BlackboxError::new("wasmtime executable is missing."))?;
        let Some(first) = args.first() else {
            return Err(BlackboxError::new("WASM packages must provide a .wasm entry file in entrypoint args."));
        };
        let wasm_file = app_dir.join(first);
        if !wasm_file.is_file() {
            return Err(BlackboxError::new(format!("WASM entry '{}' was not found in the application layer.", first)));
        }
        let work_dir = std::env::var("BLACKBOX_WORK").unwrap_or_default();
        let mut argv = vec![exe.display().to_string(), "run".into()];
        argv.push("--dir".into());
        argv.push(app_dir.display().to_string());
        if !work_dir.is_empty() {
            argv.push("--dir".into());
            argv.push(work_dir.clone());
        }
        argv.push(wasm_file.display().to_string());
        for a in &args[1..] {
            argv.push(a.clone());
        }
        Ok(argv)
    }
}

// ------------------------------------------------------------------ RUST

/// NEW runtime: the package declares `runtime: {type: rust, version: "1.85"}`
/// and ships `src/main.rs`; `blackbox pack` compiles it with a pinned,
/// hash-verified Rust toolchain into the application layer. Cross-compiles to
/// any target triple by pulling the matching `rust-std` package.
pub struct RustProvider;

impl RustProvider {
    const DIST_BASE: &'static str = "https://static.rust-lang.org/dist";

    fn toolchain_dir(version: &str, target: &str) -> PathBuf {
        run_dir("rust", version, target)
    }

    fn cargo_exe(dir: &Path, target: &str) -> PathBuf {
        if platform::target_info(target).map(|i| i.os == "windows").unwrap_or(false) {
            dir.join("bin").join("cargo.exe")
        } else {
            dir.join("bin").join("cargo")
        }
    }

    pub fn is_installed(version: &str, target: &str) -> bool {
        Self::cargo_exe(&Self::toolchain_dir(version, target), target).is_file()
    }

    fn toolchain_tar_name(version: &str, target: &str) -> String {
        format!("rust-{}-{}.tar.xz", version, target)
    }
    fn std_tar_name(version: &str, target: &str) -> String {
        format!("rust-std-{}-{}.tar.xz", version, target)
    }
    fn download_with_sha(url: &str, sha: &str) -> Result<Vec<u8>, BlackboxError> {
        let data = http_download(url, 900)?;
        if !sha.is_empty() && det::sha256_bytes(&data) != sha {
            return Err(RuntimeMissingError::new("Downloaded Rust toolchain file failed integrity verification.")
                .with_try("Refusing to install.")
                .into());
        }
        Ok(data)
    }

    fn ensure_toolchain(version: &str, host_triple: &str) -> Result<PathBuf, BlackboxError> {
        let dir = Self::toolchain_dir(version, host_triple);
        let cargo = Self::cargo_exe(&dir, host_triple);
        if cargo.is_file() {
            return Ok(cargo);
        }
        let asset = Self::toolchain_tar_name(version, host_triple);
        let sha_url = format!("{}/{}.sha256", Self::DIST_BASE, asset);
        let sha = std::fs::read_to_string(&std::env::temp_dir().join("blackbox-rust-skip"))
            .err()
            .map(|_| String::new())
            .unwrap_or_default();
        let _ = sha;
        // rust dist publishes .sha256 sidecars
        let sha = http_download(&sha_url, 60)
            .map(|b| String::from_utf8_lossy(&b).split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_default();
        let url = format!("{}/{}", Self::DIST_BASE, asset);
        println!("BLACKBOX: provisioning Rust {} toolchain (first use only, ~200 MB)...", version);
        let data = Self::download_with_sha(&url, &sha)?;
        let found = extract_archive_bytes(&data, ArchiveKind::TarXz, &dir, &["cargo", "cargo.exe", "rustc", "rustc.exe"])?;
        let resolved = found.or_else(|| Self::cargo_exe(&dir, host_triple).is_file().then(|| Self::cargo_exe(&dir, host_triple)));
        resolved.ok_or_else(|| RuntimeMissingError::new("Rust toolchain extraction completed but cargo is missing.").into())
    }

    fn ensure_std(version: &str, target: &str, host_triple: &str) -> Result<(), BlackboxError> {
        if target == host_triple {
            return Ok(());
        }
        let asset = Self::std_tar_name(version, target);
        let sha_url = format!("{}/{}.sha256", Self::DIST_BASE, asset);
        let sha = http_download(&sha_url, 60)
            .map(|b| String::from_utf8_lossy(&b).split_whitespace().next().unwrap_or("").to_string())
            .unwrap_or_default();
        let url = format!("{}/{}", Self::DIST_BASE, asset);
        println!("BLACKBOX: fetching rust-std for {} (first use only, ~30 MB)...", target);
        let data = Self::download_with_sha(&url, &sha)?;
        let stage = std::env::temp_dir().join(format!("blackbox-std-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&stage);
        std::fs::create_dir_all(&stage).map_err(|e| BlackboxError::new("Could not stage rust-std").with_detail(e.to_string()))?;
        for (name, bytes) in tar_xz_extract(&data)? {
            let norm = name.replace('\\', "/");
            if norm.split('/').any(|c| c == "..") {
                continue;
            }
            let target_path = stage.join(&norm);
            if norm.ends_with('/') {
                let _ = std::fs::create_dir_all(&target_path);
            } else {
                if let Some(p) = target_path.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let _ = std::fs::write(&target_path, &bytes);
            }
        }
        // rust-std unpacks as rust-std-<ver>-<target>/lib/rustlib/<target>/
        let entry = stage
            .read_dir()
            .ok()
            .and_then(|mut d| d.next())
            .and_then(|e| e.ok())
            .map(|e| e.path())
            .unwrap_or_else(|| stage.clone());
        let dl = entry.join("lib").join("rustlib").join(target);
        if dl.is_dir() {
            let tc = Self::toolchain_dir(version, host_triple);
            let dst = tc.join("lib").join("rustlib").join(target);
            if dst.exists() {
                let _ = std::fs::remove_dir_all(&dst);
            }
            let _ = std::fs::create_dir_all(dst.parent().unwrap());
            let _ = std::fs::rename(&dl, &dst);
        }
        let _ = std::fs::remove_dir_all(&stage);
        Ok(())
    }
}

/// Build a Rust package: pinned toolchain (or host cargo, when
/// BLACKBOX_USE_HOST_CARGO=1) target triples, produces the binary bytes.
pub fn rust_build_binary(
    version: &str,
    target: &str,
    source_dir: &Path,
) -> Result<Vec<u8>, BlackboxError> {
    let host_triple = platform::current_triple();
    let use_host = std::env::var("BLACKBOX_USE_HOST_CARGO").is_ok_and(|v| v == "1");
    let (cargo_path, is_host) = if use_host {
        if let Some(c) = platform::which("cargo") {
            (c, true)
        } else {
            return Err(BlackboxError::new("BLACKBOX_USE_HOST_CARGO=1 but no cargo on PATH.")
                .with_try("Install cargo, or unset the flag to let BLACKBOX fetch a pinned toolchain."));
        }
    } else {
        (RustProvider::ensure_toolchain(version, &host_triple)?, false)
    };
    if !is_host {
        RustProvider::ensure_std(version, target, &host_triple)?;
        // cargo from the dist uses rustc next to it; override via env
    }
    let tc_dir = if is_host {
        None
    } else {
        Some(RustProvider::toolchain_dir(version, &host_triple))
    };
    let build = std::env::temp_dir().join(format!("blackbox-rust-build-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&build);
    std::fs::create_dir_all(&build).map_err(|e| BlackboxError::new("Could not stage rust build dir").with_detail(e.to_string()))?;
    copy_tree(source_dir, &build)?;
    let mut cmd = std::process::Command::new(&cargo_path);
    cmd.arg("build").arg("--release");
    let rustc_path = tc_dir
        .as_ref()
        .map(|d| d.join("bin").join(if cfg!(windows) { "rustc.exe" } else { "rustc" }));
    let mut env: BTreeMap<String, String> = BTreeMap::new();
    if let Some(tc) = &tc_dir {
        if let Some(rc) = &rustc_path {
            if rc.is_file() {
                env.insert("RUSTC".into(), rc.display().to_string());
            }
        }
        env.insert("CARGO_HOME".into(), build.join(".cargo-home").display().to_string());
    }
    let _ = cmd.current_dir(&build).arg("--target").arg(target);
    if is_host && std::env::var_os("RUSTUP_TOOLCHAIN").is_none() && platform::which("rustup").is_none() {
        // Host cargo for a different target usually requires rustup stds;
        // let it fail naturally with the rustc error below (clear message).
        let _ = ();
    }
    for (k, v) in &env {
        cmd.env(k, v);
    }
    let out = cmd.output();
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return Err(BlackboxError::new("Could not run cargo for the Rust package.").with_detail(format!("{}", e))
                .with_try("Run 'blackbox doctor' to check the toolchain; or unset BLACKBOX_USE_HOST_CARGO."));
        }
    };
    if !out.status.success() {
        let log = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = log.lines().filter(|l| !l.is_empty()).rev().take(12).collect();
        return Err(BlackboxError::new(format!("Rust package build failed for target {}.", target))
            .with_detail(tail.into_iter().rev().collect::<Vec<_>>().join("\n"))
            .with_try("Check src/main.rs for compile errors."));
    }
    // locate binary: cargo emits target/<triple>/release/<binname>
    let bin_dir = build.join("target").join(target).join("release");
    let bin = find_release_binary(&bin_dir)?;
    Ok(std::fs::read(&bin).map_err(|e| BlackboxError::new("Could not read built binary.").with_detail(e.to_string()))?)
}

fn find_release_binary(dir: &Path) -> Result<PathBuf, BlackboxError> {
    if !dir.is_dir() {
        return Err(BlackboxError::new("cargo did not produce a target release directory."));
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() {
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if cfg!(windows) {
                    if name.ends_with(".exe") && !name.starts_with('\\') && name != "build_script_build" && name != "rustc" {
                        candidates.push(p);
                    }
                } else if name.ends_with(".d") || name.ends_with(".rlib") || name.ends_with(".rmeta") || name.ends_with(".o") {
                    continue;
                } else {
                    candidates.push(p);
                }
            }
        }
    }
    candidates.sort();
    candidates.first().cloned().ok_or_else(|| {
        BlackboxError::new("cargo built successfully but produced no binary.")
            .with_try("Add a [[bin]] or a src/main.rs to the package.")
    })
}

fn copy_tree(src: &Path, dst: &Path) -> Result<(), BlackboxError> {
    for entry in walkdir::WalkDir::new(src) {
        let e = entry.map_err(|e| BlackboxError::new("Could not read source tree").with_detail(e.to_string()))?;
        let rel = e.path().strip_prefix(src).map(|p| p.to_path_buf()).unwrap_or_default();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = dst.join(&rel);
        if e.file_type().is_dir() {
            std::fs::create_dir_all(&target).map_err(|x| BlackboxError::new("Could not create build dir").with_detail(x.to_string()))?;
        } else if e.file_type().is_file() || e.file_type().is_symlink() {
            if let Ok(m) = std::fs::metadata(e.path()) {
                if m.len() > 64 * 1024 * 1024 {
                    continue;
                }
            }
            if let Ok(data) = std::fs::read(e.path()) {
                if let Some(p) = target.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let _ = std::fs::write(&target, data);
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ registry

pub struct ProviderRegistry {
    pub providers: Vec<Box<dyn RuntimeProvider>>,
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self {
            providers: vec![
                Box::new(PythonProvider),
                Box::new(NodeProvider),
                Box::new(NativeProvider),
                Box::new(WasmProvider),
                Box::new(RustProvider),
            ],
        }
    }
}

pub fn get_provider(rtype: &str) -> Result<Box<dyn RuntimeProvider>, BlackboxError> {
    let reg = ProviderRegistry::default();
    for p in reg.providers {
        if p.rtype() == rtype {
            return Ok(p);
        }
    }
    Err(BlackboxError::new(format!("No BLACKBOX runtime provider for '{}'.", rtype))
        .with_detail("Available: native, node, python, rust, wasm")
        .with_try("See docs/architecture.md for how providers are added."))
}

// ------------------------------------------------------------- manager

pub struct RuntimeManager;

impl RuntimeManager {
    pub fn import_tarball(path: &Path) -> Result<BTreeMap<String, String>, BlackboxError> {
        let base = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if !base.starts_with("cpython-") || !base.ends_with(".tar.gz") {
            return Err(RuntimeMissingError::new(format!("'{}' is not a python-build-standalone install_only tarball.", base)).into());
        }
        let stem = base["cpython-".len()..base.len() - ".tar.gz".len()].to_string();
        let Some((full, rest)) = stem.split_once('+') else {
            return Err(RuntimeMissingError::new(format!("Unsupported runtime build: {}", base)).into());
        };
        let tag = rest.split('-').next().unwrap_or("").to_string();
        let triple = rest[tag.len() + 1..].trim_end_matches("-install_only").to_string();
        let family: String = full.split('.').take(2).collect::<Vec<_>>().join(".");
        let known_triple = crate::platform::target_info(&triple).is_ok();
        let known_family = PINNED_PYTHON.iter().any(|(f, _, _)| *f == family);
        if !known_triple || !known_family {
            return Err(RuntimeMissingError::new(format!("Unsupported runtime build: {}", base)).into());
        }
        let actual = det::sha256_file(path)
            .map_err(|e| BlackboxError::new("Could not hash the tarball").with_detail(e.to_string()))?;
        let sidecar = PathBuf::from(format!("{}.sha256", path.display()));
        if sidecar.is_file() {
            if let Ok(text) = std::fs::read_to_string(&sidecar) {
                let expected = text.split_whitespace().next().unwrap_or("");
                if !expected.is_empty() && expected != actual {
                    return Err(RuntimeMissingError::new("Tarball does not match its .sha256 sidecar; refusing to install.").into());
                }
            }
        }
        let data = std::fs::read(path).map_err(|e| BlackboxError::new("Could not read the tarball").with_detail(e.to_string()))?;
        let _ = extract_archive_bytes(&data, ArchiveKind::TarGz, &run_dir("python", &family, &triple), &["python3", "python.exe"])?;
        let mut out = BTreeMap::new();
        out.insert("family".into(), family);
        out.insert("full".into(), full.to_string());
        out.insert("target".into(), triple);
        out.insert("sha256".into(), actual);
        Ok(out)
    }

    pub fn installed() -> Vec<(String, String, bool)> {
        let triple = platform::current_triple();
        let mut res = Vec::new();
        for (fam, _, _) in PINNED_PYTHON {
            res.push(("python".into(), fam.to_string(), PythonProvider::is_installed(fam, &triple)));
        }
        for maj in NODE_MAJORS {
            res.push(("node".into(), maj.to_string(), NodeProvider::is_installed(maj, &triple)));
        }
        let wasm_versions = ["24.0.0", "25.0.0", "26.0.0", "27.0.0"];
        for v in wasm_versions {
            res.push(("wasm".into(), v.to_string(), WasmProvider::is_installed(v, &triple)));
        }
        let rust_versions = ["1.85.0", "1.86.0"];
        for v in rust_versions {
            res.push(("rust".into(), v.to_string(), RustProvider::is_installed(v, &triple)));
        }
        res
    }
}

pub fn pip_python() -> PathBuf {
    PythonProvider::executable("3.12", &platform::current_triple())
}

/// Python used for pip resolution: BLACKBOX-provisioned standalone (host
/// triple) - never the host's Python, exactly like the runtime contract.
pub fn ensure_pip_python() -> Result<PathBuf, BlackboxError> {
    static PROVISION: std::sync::OnceLock<std::result::Result<PathBuf, String>> =
        std::sync::OnceLock::new();
    let r: &std::result::Result<PathBuf, String> = PROVISION.get_or_init(|| {
        let target = platform::current_triple();
        let exe = pip_python();
        if exe.is_file() {
            return Ok(exe);
        }
        match PythonProvider.ensure("3.12", &target, None) {
            Ok(Some(p)) => Ok(p),
            Ok(None) => Err("Pip python could not be provisioned.".to_string()),
            Err(e) => Err(e.summary),
        }
    });
    r.clone().map_err(|e| BlackboxError::new(format!("Pip python could not be provisioned: {}", e)))
}

impl RuntimeProvider for RustProvider {
    fn rtype(&self) -> &'static str {
        "rust"
    }
    fn ensure(&self, version: &str, target: &str, _pin: Option<&Value>) -> Result<Option<PathBuf>, BlackboxError> {
        // at run time the package binary IS the runtime (like native);
        // the cargo toolchain is a pack-time concern.
        check_target(target)?;
        Ok(None)
    }
    fn env(&self, _exe: Option<&Path>, _site_dir: &Path, _app_dir: &Path, _target: &str) -> BTreeMap<String, String> {
        BTreeMap::new()
    }
    fn resolve_command(
        &self,
        command: &str,
        args: &[String],
        _exe: Option<&Path>,
        app_dir: &Path,
        _manifest: &Manifest,
    ) -> Result<Vec<String>, BlackboxError> {
        NativeProvider.resolve_command(command, args, None, app_dir, _manifest)
    }
}

// ---------------------------------------------------------------- runner

#[path = "runtime_runner.rs"]
mod runner;
pub use runner::{build_launch, execute, exec_interactive, RunContext, Launch, SHIM_NAMES};

/// Compatibility facade so callers can `crate::runtime::providers::...`.
pub mod providers {
    pub use super::*;
}
