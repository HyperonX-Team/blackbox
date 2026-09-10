//! Dependency resolution and locking for Python and Node BLACKBOXes.
//!
//! python: pip `--dry-run --report` against the *target* interpreter/platform
//! (using the BLACKBOX-provisioned Python, never the host's), so a Linux
//! package locks Linux wheels even when built on Windows. Wheels are then
//! fetched from their recorded URLs, hash-verified, and expanded into an
//! isolated site-packages tree that becomes one deterministic layer.
//!
//! node: npm install into an isolated dir; package-lock-derived entry list;
//! node_modules becomes the dependency layer.

use crate::deterministic as det;
use crate::error::BlackboxError;
use crate::storage::CAS;
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

pub fn read_requirements(source_dir: &Path, requirements_file: &str) -> Vec<String> {
    let p = source_dir.join(requirements_file);
    if !p.is_file() {
        return Vec::new();
    }
    std::fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

/// Resolve a lockfile for one target. For `node`, the interpreter pin
/// (version/asset/url/sha256) is recorded in `runtime`.
pub fn build_lock_for_target(
    source_dir: &Path,
    manifest: &mut crate::manifest::Manifest,
    target: &str,
) -> Result<Value, BlackboxError> {
    let rt = &manifest.runtime;
    let mut lock = serde_json::json!({
        "lock_version": 1,
        "runtime": {"type": rt.rtype, "version": rt.version, "target": target},
        "packages": [],
    });
    match rt.rtype.as_str() {
        "python" => {
            let reqs = read_requirements(source_dir, &manifest.requirements);
            let reqs: Vec<String> = reqs
                .iter()
                .map(|r| r.split('#').next().unwrap_or("").trim().to_string())
                .filter(|r| !r.is_empty())
                .collect();
            if reqs.is_empty() {
                return Ok(lock);
            }
            let resolved = pip_lock_requirements(&reqs, &rt.version, target)?;
            lock["packages"] = resolved.get("packages").cloned().unwrap_or(Value::Null);
        }
        "node" => {
            let node_exe = crate::runtime::providers::ensure_node_for_lock(&rt.version)?;
            let pj = source_dir.join(&manifest.requirements);
            if !pj.is_file() {
                return Ok(lock);
            }
            let (npkgs, _) = node_lock(&pj, &node_exe)?;
            let pin = crate::runtime::providers::node_pin_for_lock(&rt.version, target)?;
            if let Some(runtime_obj) = lock.get_mut("runtime").and_then(|r| r.as_object_mut()) {
                for (k, v) in pin {
                    runtime_obj.insert(k, Value::String(v));
                }
            }
            lock["packages"] = npkgs;
        }
        "wasm" => {
            // pin the wasmtime release identity at pack time
            let pin = crate::runtime::providers::wasm_pin_for_lock(&rt.version, target)?;
            if let Some(runtime_obj) = lock.get_mut("runtime").and_then(|r| r.as_object_mut()) {
                for (k, v) in pin {
                    runtime_obj.insert(k, Value::String(v));
                }
            }
        }
        _ => {}
    }
    Ok(lock)
}

// ------------------------------------------------------------------- pip

pub fn run_pip(args: &[&str]) -> Result<std::process::Output, BlackboxError> {
    let py = crate::runtime::providers::ensure_pip_python()?;
    let out = std::process::Command::new(&py)
        .arg("-m")
        .arg("pip")
        .args(args)
        .output()
        .map_err(|e| BlackboxError::new("Could not run pip (via the provisioned Python).")
            .with_detail(format!("{}", e))
            .with_try("BLACKBOX needs to provision a standalone Python to resolve dependencies."))?;
    Ok(out)
}

fn pip_lock_requirements(reqs: &[String], python_version: &str, target_triple: &str) -> Result<Value, BlackboxError> {
    let tmp = std::env::temp_dir().join(format!("blackbox-lock-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| BlackboxError::new("Could not create the resolve temp dir").with_detail(e.to_string()))?;
    let req_file = tmp.join("requirements.txt");
    let report_file = tmp.join("report.json");
    std::fs::write(&req_file, format!("{}\n", reqs.join("\n")))
        .map_err(|e| BlackboxError::new("Could not write the requirements snapshot").with_detail(e.to_string()))?;
    let flags = crate::platform::pip_target_flags(target_triple, python_version)?;
    let mut args: Vec<String> = vec![
        "install".into(),
        "--dry-run".into(),
        "--ignore-installed".into(),
        "--disable-pip-version-check".into(),
        "--target".into(),
        tmp.join("resolve-only").to_string_lossy().to_string(),
        "--report".into(),
        report_file.to_string_lossy().to_string(),
        "--only-binary".into(),
        ":all:".into(),
        "-r".into(),
        req_file.to_string_lossy().to_string(),
    ];
    args.extend(flags);
    let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = run_pip(&arg_refs)?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        let log = tail(&err, 15);
        return Err(BlackboxError::new("Could not resolve the requested dependencies.")
            .with_detail(log)
            .with_try(
                "Check the version pins in requirements.txt.\n\
                 Confirm the packages publish wheels for Python {ver} on {target} (source-only packages are not supported).",
            ));
    }
    let report: Value = serde_json::from_slice(&std::fs::read(&report_file).unwrap_or_default())
        .map_err(|e| BlackboxError::new("pip returned an unreadable resolution report.").with_detail(e.to_string()))?;
    let mut packages: Vec<Value> = Vec::new();
    if let Some(items) = report.get("install").and_then(|v| v.as_array()) {
        for item in items {
            let meta = item.get("metadata").cloned().unwrap_or(Value::Null);
            let di = item.get("download_info").cloned().unwrap_or(Value::Null);
            let url = di.get("url").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or_default();
            let sha = di
                .get("archive_info")
                .and_then(|a| a.get("hashes"))
                .and_then(|h| h.get("sha256"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_default();
            let name = meta.get("name").and_then(|v| v.as_str()).unwrap_or("").trim().to_lowercase().replace('_', "-");
            let version = meta.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            packages.push(serde_json::json!({"name": name, "version": version, "url": url, "sha256": sha}));
        }
    }
    packages.sort_by(|a, b| {
        let na = a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let nb = b.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
        na.cmp(&nb)
    });
    Ok(serde_json::json!({"lock_version": 1, "packages": packages}))
}

pub fn fetch_locked(lock: &Value, cas: &CAS) -> Result<PathBuf, BlackboxError> {
    let wheels_dir = cas.root.join("wheels").join(format!("resolve-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&wheels_dir);
    std::fs::create_dir_all(&wheels_dir).map_err(|e| BlackboxError::new("Could not create wheels dir").with_detail(e.to_string()))?;
    let Some(packages) = lock.get("packages").and_then(|v| v.as_array()) else {
        return Ok(wheels_dir);
    };
    for pkg in packages {
        let name = pkg.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let url = pkg.get("url").and_then(|v| v.as_str()).unwrap_or("");
        let sha = pkg.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
        if url.is_empty() || sha.is_empty() {
            return Err(BlackboxError::new(format!("Lockfile entry for '{}' is incomplete (missing url or sha256).", name))
                .with_try("Delete blackbox.lock and run 'blackbox pack' again to regenerate it."));
        }
        let ref_str = format!("sha256:{}", sha);
        let obj_path = if cas.has(&ref_str) && cas.verify(&ref_str) {
            cas.get_path(&ref_str).unwrap()
        } else {
            let data = crate::serve::http_get(url)
                .map_err(|e| BlackboxError::new(format!("Could not download {}", url)).with_detail(format!("{}", e)).with_try(
                    "BLACKBOX needs one-time network access to fetch locked dependencies.\nIf the dependency is already cached, no network is required."))?;
            let got = det::sha256_bytes(&data);
            if got != sha {
                return Err(BlackboxError::new(format!("Downloaded '{}' does not match the hash recorded in the lockfile.", name))
                    .with_try("The package may have been tampered with upstream. Aborting."));
            }
            cas.put_bytes(&data).unwrap();
            cas.get_path(&ref_str).unwrap()
        };
        let filename = url.rsplit('/').next().unwrap_or("wheel.whl").split('#').next().unwrap_or("");
        let dest = wheels_dir.join(filename);
        std::fs::copy(&obj_path, &dest)
            .map_err(|e| BlackboxError::new(format!("Could not stage wheel '{}'.", filename)).with_detail(e.to_string()))?;
    }
    Ok(wheels_dir)
}

/// Expand locked wheels into an isolated site-packages tree {arcname: bytes}.
pub fn build_site_packages(lock: &Value, wheels_dir: &Path) -> Result<BTreeMap<String, Option<Vec<u8>>>, BlackboxError> {
    let _ = lock;
    let mut files: BTreeMap<String, Option<Vec<u8>>> = BTreeMap::new();
    let mut wheel_files = Vec::new();
    if wheels_dir.is_dir() {
        for entry in walkdir::WalkDir::new(wheels_dir) {
            if let Ok(e) = entry {
                if e.file_type().is_file() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.ends_with(".whl") {
                        wheel_files.push(name);
                    }
                }
            }
        }
    }
    wheel_files.sort();
    for whl in wheel_files {
        let path = wheels_dir.join(&whl);
        let f = std::fs::File::open(&path)
            .map_err(|e| BlackboxError::new(format!("Could not open wheel '{}'.", whl)).with_detail(e.to_string()))?;
        let mut zip = zip::ZipArchive::new(f)
            .map_err(|e| BlackboxError::new(format!("Wheel '{}' is not a valid zip.", whl)).with_detail(e.to_string()))?;
        for i in 0..zip.len() {
            let mut entry = zip.by_index(i)
                .map_err(|e| BlackboxError::new(format!("Wheel '{}' is unreadable.", whl)).with_detail(e.to_string()))?;
            let name = entry.name().replace('\\', "/");
            if name.ends_with('/') {
                files.insert(format!("{}/", name.trim_end_matches('/')), None);
                continue;
            }
            if name.split('/').any(|c| c == "..") {
                return Err(BlackboxError::new(format!("Wheel '{}' contains an unsafe path: {}", whl, name)));
            }
            if name.ends_with(".dist-info/direct_url.json") || name.ends_with("/RECORD") {
                continue; // machine-specific metadata - stripped for determinism
            }
            let mut data = Vec::new();
            entry
                .read_to_end(&mut data)
                .map_err(|e| BlackboxError::new(format!("Wheel '{}' member '{}' unreadable.", whl, name)).with_detail(e.to_string()))?;
            files.insert(name, Some(data));
        }
    }
    Ok(files)
}

pub fn deps_digest(lock: &Value) -> String {
    let mut canon = Vec::new();
    if let Some(packages) = lock.get("packages").and_then(|v| v.as_array()) {
        let list: Vec<Value> = packages
            .iter()
            .filter_map(|p| {
                let name = p.get("name").and_then(|v| v.as_str())?;
                let sha = p.get("sha256").and_then(|v| v.as_str())?;
                Some(serde_json::json!({"name": name, "sha256": sha}))
            })
            .collect();
        canon = det::canon_json(&serde_json::to_value(list).unwrap());
    }
    format!("sha256:{}", det::sha256_bytes(&canon))
}

fn tail(text: &str, n: usize) -> String {
    text.lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .rev()
        .take(n)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}

// ------------------------------------------------------------------- npm

pub fn node_staging_dir() -> PathBuf {
    std::env::temp_dir().join(format!("blackbox-npm-{}", std::process::id()))
}

pub fn node_lock(package_json: &Path, node_exe: &Path) -> Result<(Value, Option<BTreeMap<String, String>>), BlackboxError> {
    let tmp = node_staging_dir();
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| BlackboxError::new("Could not create npm install dir").with_detail(e.to_string()))?;
    std::fs::copy(package_json, tmp.join("package.json"))
        .map_err(|e| BlackboxError::new("Could not copy package.json into the staging dir").with_detail(e.to_string()))?;
    let npm = if cfg!(windows) { "npm.cmd" } else { "npm" };
    let node_dir = node_exe.parent().map(|d| d.to_path_buf()).unwrap_or_default();
    let mut paths = vec![node_dir.clone()];
    if let Some(sys) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&sys));
    }
    let path_val = std::env::join_paths(paths).unwrap_or_default();
    let out = std::process::Command::new(npm)
        .arg("install")
        .arg("--omit=dev")
        .arg("--no-audit")
        .arg("--no-fund")
        .arg("--loglevel=error")
        .arg("--ignore-scripts")
        .current_dir(&tmp)
        .env_remove("NODE_PATH")
        .env("PATH", path_val)
        .output()
        .map_err(|e| BlackboxError::new("Could not run npm.").with_detail(format!("{}", e)).with_try("Check the version pins in package.json."))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).to_string();
        let log = tail(&err, 15);
        return Err(BlackboxError::new("npm could not resolve the dependencies in package.json.")
            .with_detail(log)
            .with_try("Check the version pins in package.json."));
    }
    let mut lock_json = serde_json::json!({"packages": [], "node_modules": true});
    let plock_path = tmp.join("package-lock.json");
    if plock_path.is_file() {
        let plock: Value = serde_json::from_slice(&std::fs::read(&plock_path).unwrap_or_default())
            .map_err(|e| BlackboxError::new("package-lock.json is invalid JSON.").with_detail(e.to_string()))?;
        let mut entries: Vec<Value> = Vec::new();
        if let Some(pkgs) = plock.get("packages").and_then(|v| v.as_object()) {
            let mut keys: Vec<&String> = pkgs.keys().collect();
            keys.sort();
            for pkg in keys {
                if pkg.is_empty() || pkg == "node_modules/" {
                    continue;
                }
                let meta = &pkgs[pkg];
                let Some(version) = meta.get("version").and_then(|v| v.as_str()) else {
                    continue;
                };
                let name = pkg.rsplit("node_modules/").next().unwrap_or("").to_string();
                let integrity = meta.get("integrity").and_then(|v| v.as_str()).unwrap_or("").to_string();
                entries.push(serde_json::json!({"name": name, "version": version, "integrity": integrity}));
            }
        }
        lock_json["packages"] = Value::Array(entries);
    }
    let pin = None;
    Ok((lock_json, pin))
}

pub fn node_site_files(source_dir: &Path, lock: &Value) -> Result<(BTreeMap<String, Option<Vec<u8>>>, Vec<String>), BlackboxError> {
    let _ = lock;
    let pj = source_dir.join("package.json");
    let node_exe = crate::runtime::providers::ensure_node_for_lock("22")?;
    let (_, _) = node_lock(&pj, &node_exe)?;
    let staging = node_staging_dir();
    let (files, execs) = det::collect_tree(&staging, &[])
        .map_err(|e| BlackboxError::new("Could not collect npm staging tree").with_detail(e.to_string()))?;
    let _ = std::fs::remove_dir_all(&staging);
    Ok((files, execs))
}
