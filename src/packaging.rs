//! The .blackbox package format: deterministic ZIP container building and
//! reading, layer installation, multi-target fat packages, thin packages,
//! whole-package encryption and composite pipelines.
//!
//! Members:
//!   manifest.json      canonical JSON of the normalized manifest
//!   blackbox.lock      YAML lockfile: exact versions, urls, sha256
//!   application.tar.zst  deterministic layer (source + assets)
//!   dependencies.tar.zst deterministic dependency layer (if any)
//!   layers.json        layer index: {kind, target, digest, members, exec}
//!   checksums.json     sha256 of every other member (integrity root)
//!   signature.json     optional Ed25519 signature
//!   encrypted.json     optional whole-package encryption of private members

use crate::deterministic as det;
use crate::error::{BlackboxError, IntegrityError, PackageFormatError};
use crate::manifest::{load_manifest, Manifest};
use crate::runtime::RunContext;
use crate::storage::{ensure_home, CAS};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

pub const MANIFEST: &str = "manifest.json";
pub const LOCK: &str = "blackbox.lock";
pub const APP_LAYER: &str = "application.tar.zst";
pub const DEPS_LAYER: &str = "dependencies.tar.zst";
pub const LAYERS_INDEX: &str = "layers.json";
pub const CHECKSUMS: &str = "checksums.json";
pub const SIGNATURE: &str = "signature.json";
pub const SECRETS: &str = "secrets.json";
pub const PROVENANCE: &str = "provenance.json";
pub const ENCRYPTED: &str = "encrypted.json";
pub const STAGES: &str = "stages.json";

pub const MEMBER_ORDER: &[&str] = &[
    MANIFEST,
    LOCK,
    APP_LAYER,
    DEPS_LAYER,
    LAYERS_INDEX,
    CHECKSUMS,
    SIGNATURE,
    SECRETS,
    PROVENANCE,
    ENCRYPTED,
    STAGES,
];

pub const MANIFEST_NAME: &str = "blackbox.yaml";

pub const EXCLUDE_AT_PACK: &[&str] = &["output", "input", ".blackbox", "__pycache__", "blackbox.lock", "node_modules"];

// ---------------------------------------------------------------- zip helpers

fn zip_fixed_date() -> zip::DateTime {
    // 1980-01-01, minimum representable ZIP date - the fixed epoch of the format
    zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).expect("valid fixed zip date")
}

#[allow(clippy::too_many_arguments)]
fn add_to_zip(
    zip: &mut zip::ZipWriter<Cursor<Vec<u8>>>,
    name: &str,
    data: &[u8],
    is_dir: bool,
    mode: u32,
) -> Result<(), PackageFormatError> {
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(mode)
        .last_modified_time(zip_fixed_date());
    zip.start_file(name, options)
        .map_err(|e| PackageFormatError::new(format!("Could not write ZIP member '{}'", name)).with_detail(e.to_string()))?;
    zip.write_all(data)
        .map_err(|e| PackageFormatError::new(format!("Could not write ZIP member '{}'", name)).with_detail(e.to_string()))?;
    let _ = is_dir;
    Ok(())
}

pub fn write_plain_zip(members: &[String]) -> Result<Vec<u8>, PackageFormatError> {
    let cursor = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    for name in members {
        let mut h = zip::write::FileOptions::default();
        h = h
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(zip_fixed_date())
            .unix_permissions(0o644);
        zip.start_file(name, h)
            .map_err(|e| PackageFormatError::new(format!("Could not write ZIP member '{}'", name)).with_detail(e.to_string()))?;
    }
    let cursor = zip.finish().map_err(|e| PackageFormatError::new("Could not finalize ZIP").with_detail(e.to_string()))?;
    Ok(cursor.into_inner())
}

/// Serialize members into the deterministic outer ZIP. When `add_checksums`
/// is true, `checksums.json` is computed over every other member and appended
/// (it must be the last member).
pub fn write_deterministic_zip(
    members: &BTreeMap<String, Vec<u8>>,
    add_checksums: bool,
) -> Result<Vec<u8>, PackageFormatError> {
    // member order: fixed first, then anything extra (sorted) - matches the
    // Python MVP's ordering rule
    let mut order: Vec<String> = Vec::new();
    for name in MEMBER_ORDER {
        if members.contains_key(*name) {
            order.push(name.to_string());
        }
    }
    let mut extra: Vec<&String> = members.keys().filter(|k| !MEMBER_ORDER.contains(&k.as_str())).collect();
    extra.sort();
    for e in extra {
        order.push(e.clone());
    }
    order.retain(|k| k != CHECKSUMS);

    let cursor = Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    for name in &order {
        let data = members.get(name).unwrap();
        add_to_zip(&mut zip, name, data, false, 0o644)?;
    }
    if add_checksums {
        let mut checksums = BTreeMap::new();
        for name in &order {
            let data = members.get(name).unwrap();
            checksums.insert(name.clone(), det::sha256_bytes(data));
        }
        let payload = det::canon_json(&serde_json::json!({"sha256": checksums}));
        add_to_zip(&mut zip, CHECKSUMS, &payload, false, 0o644)?;
    }
    let cursor = zip
        .finish()
        .map_err(|e| PackageFormatError::new("Could not finalize .blackbox ZIP").with_detail(e.to_string()))?;
    Ok(cursor.into_inner())
}

pub fn read_zip_all(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, PackageFormatError> {
    let file = std::fs::File::open(path).map_err(|e| {
        PackageFormatError::new(format!("No such BLACKBOX file: {}", path.display())).with_detail(e.to_string())
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| {
        PackageFormatError::new(
            "'{}' is not a readable BLACKBOX package.",
        )
        .with_detail("The file is truncated or not in the .blackbox format.")
        .with_try("Re-copy the original file. .blackbox packages are self-contained; a partial transfer corrupts them.")
    })?;
    let mut members = BTreeMap::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            PackageFormatError::new("Could not read a ZIP member.")
                .with_detail(e.to_string())
        })?;
        let name = entry.name().to_string();
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|e| PackageFormatError::new(format!("Could not read member '{}'", name)).with_detail(e.to_string()))?;
        members.insert(name, data);
    }
    Ok(members)
}

// ------------------------------------------------------------------ Package

#[derive(Debug, Clone)]
pub struct Package {
    pub path: PathBuf,
    pub members: BTreeMap<String, Vec<u8>>,
    pub manifest: Manifest,
    pub checksums: BTreeMap<String, String>,
    pub encrypted: bool,
}

impl Package {
    pub fn content_digest(&self) -> String {
        let mut canon_map = BTreeMap::new();
        for (k, v) in &self.checksums {
            if k != SIGNATURE {
                canon_map.insert(k.clone(), Value::String(v.clone()));
            }
        }
        let canon = det::canon_json(&serde_json::to_value(canon_map).unwrap());
        format!("sha256:{}", det::sha256_bytes(&canon))
    }

    pub fn package_id(&self) -> String {
        format!(
            "{}@{}-{}",
            self.manifest.name,
            self.manifest.version,
            &self.content_digest()[7..19]
        )
    }
}

fn ensure_required_members(members: &BTreeMap<String, Vec<u8>>) -> Result<(), PackageFormatError> {
    if !members.contains_key(MANIFEST) || !members.contains_key(CHECKSUMS) {
        return Err(PackageFormatError::new("Package is missing required members.")
            .with_detail(format!(
                "Members present: {}",
                members.keys().cloned().collect::<Vec<_>>().join(", ")
            )));
    }
    // composite packages carry stages/ + stages.json; thin packages carry a
    // layers index that names blobs to fetch - neither embeds the app tar
    if !members.contains_key(STAGES) && !members.contains_key(LAYERS_INDEX) {
        return Err(PackageFormatError::new("Layer index is missing.")
            .with_detail(format!(
                "Members present: {}",
                members.keys().cloned().collect::<Vec<_>>().join(", ")
            )));
    }
    Ok(())
}

/// Decrypt `encrypted.json` if present; returns the raw member map for the
/// private members and the decrypted members (empty ciphertexts for those).
pub fn decrypt_encrypted_members(
    members: &BTreeMap<String, Vec<u8>>,
) -> Result<(BTreeMap<String, Vec<u8>>, bool), BlackboxError> {
    let Some(payload) = members.get(ENCRYPTED) else {
        return Ok((members.clone(), false));
    };
    let blob: Value = serde_json::from_slice(payload)
        .map_err(|e| BlackboxError::new("Package has a malformed encrypted.json member.").with_detail(e.to_string()))?;
    let member_blobs = blob.get("members").and_then(|v| v.as_object()).ok_or_else(|| {
        BlackboxError::new("encrypted.json is missing its 'members' listing.")
    })?;
    let mut out = members.clone();
    for (name, enc_json) in member_blobs {
        let plain = crate::crypto::open_member_bytes(enc_json)?;
        out.insert(name.clone(), plain);
    }
    Ok((out, true))
}

/// Open a .blackbox file: verify integrity, decrypt (if sealed to this key),
/// parse the manifest.
fn read_zip_all_boxed(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, Box<dyn std::error::Error>> {
    read_zip_all(path).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

pub fn open_package(path: &Path) -> Result<Package, BlackboxError> {
    let mut members = read_zip_all_boxed(path).map_err(|e| {
        BlackboxError::new("Could not read the package container.").with_detail(e.to_string())
    })?;
    ensure_required_members(&members)?;

    // encrypted first: checksums cover the encrypted member so integrity
    // verification happens before decryption
    let (decrypted, enc) = decrypt_encrypted_members(&members)?;
    members = decrypted;
    let encrypted = enc;

    let checksums: Value = serde_json::from_slice(&members[CHECKSUMS]).map_err(|e| {
        PackageFormatError::new("checksums.json is not valid JSON.").with_detail(e.to_string())
    })?;
    let checksums: BTreeMap<String, String> = serde_json::from_value(checksums.get("sha256").cloned().unwrap_or(Value::Null))
        .unwrap_or_default();
    for (name, want) in &checksums {
        let Some(data) = members.get(name) else {
            return Err(IntegrityError::new(format!("Package integrity check failed: member '{}' is missing.", name)).into());
        };
        let got = det::sha256_bytes(data);
        if got != *want {
            return Err(IntegrityError::new(format!(
                "Package integrity check failed: '{}' does not match its recorded hash.",
                name
            ))
            .with_detail(format!("expected {}\nactual   {}", want, got))
            .with_try("The package was modified after it was built. Re-pack or obtain a fresh copy.").into());
        }
    }

    let manifest_json = &members[MANIFEST];
    let manifest_text = String::from_utf8_lossy(manifest_json);
    let manifest = load_manifest(&manifest_text)
        .map_err(|e| {
            let be: BlackboxError = e.into();
            PackageFormatError::new("Package manifest is not a valid BLACKBOX manifest.").with_detail(be.summary)
        })?;

    Ok(Package {
        path: path.to_path_buf(),
        members,
        manifest,
        checksums,
        encrypted,
    })
}

pub fn yaml_sorted_str(v: &Value) -> String {
    let sorted = det::json_sorted(v);
    let s = serde_yaml::to_string(&sorted).unwrap_or_default();
    s
}

// ---------------------------------------------------------------- install

/// {kind: dir} materialized for run. Multi-target packages pick the layers
/// matching the host triple.
pub fn install(pkg: &Package, cas: &CAS, quiet: bool) -> Result<BTreeMap<String, Option<PathBuf>>, BlackboxError> {
    let home = ensure_home();
    let layers_json: Value = serde_json::from_slice(&pkg.members[LAYERS_INDEX])
        .map_err(|e| PackageFormatError::new("layers.json is not valid JSON.").with_detail(e.to_string()))?;
    let layers = layers_json
        .get("layers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let host_triple = crate::platform::current_triple();
    let mut dirs: BTreeMap<String, Option<PathBuf>> = BTreeMap::new();
    dirs.insert("application_dir".into(), None);
    dirs.insert("site_dir".into(), None);
    for layer in &layers {
        let target = layer.get("target").and_then(|v| v.as_str()).unwrap_or("any");
        if target != "any" && target != host_triple {
            continue;
        }
        let kind = layer.get("kind").and_then(|v| v.as_str()).unwrap_or("");
        let digest = layer.get("digest").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let file = layer.get("file").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let execs: Vec<String> = layer
            .get("exec")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let blob = pkg.members.get(&file).ok_or_else(|| {
            IntegrityError::new(format!("Package is missing layer member '{}'.", file))
        })?;
        if let Some(hex) = digest.strip_prefix("sha256:") {
            if det::sha256_bytes(blob) != hex {
                return Err(IntegrityError::new(format!("Layer digest mismatch for '{}' layer.", kind))
                    .with_try("Re-pack the package.").into());
            }
        }
        let _ = cas.put_bytes(blob);
        let dest = home.layers.join(digest.replace(":", "_")).join(kind);
        if !dest.exists() {
            if !quiet {
                println!("BLACKBOX: caching {} layer {}...", kind, &digest[..digest.len().min(19)]);
            }
            let files = det::files_from_tar(blob)?;
            let exec_refs: Vec<&str> = execs.iter().map(|s| s.as_str()).collect();
            det::extract_tree(&files, &dest, true, &exec_refs)?;
        }
        if kind == "application" {
            dirs.insert("application_dir".into(), Some(dest));
        } else if kind == "dependencies" {
            dirs.insert("site_dir".into(), Some(dest));
        }
    }
    Ok(dirs)
}

pub fn unpack_all(pkg: &Package, dest: &Path) -> Result<PathBuf, BlackboxError> {
    std::fs::create_dir_all(dest).map_err(|e| PackageFormatError::new("Could not create unpack destination").with_detail(e.to_string()))?;
    for name in [MANIFEST, LOCK, CHECKSUMS, SIGNATURE, SECRETS, PROVENANCE, ENCRYPTED, STAGES] {
        if let Some(data) = pkg.members.get(name) {
            let _ = std::fs::write(dest.join(name), data);
        }
    }
    if let Some(idx) = pkg.members.get(LAYERS_INDEX) {
        let _ = std::fs::write(dest.join(LAYERS_INDEX), idx);
    }
    let layers_json: Value = serde_json::from_slice(pkg.members.get(LAYERS_INDEX).map(|v| v.as_slice()).unwrap_or(b"{\"layers\":[]}"))
        .unwrap_or(Value::Null);
    if let Some(layers) = layers_json.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            let kind = layer.get("kind").and_then(|v| v.as_str()).unwrap_or("");
            let file = layer.get("file").and_then(|v| v.as_str()).unwrap_or("");
            let execs: Vec<String> = layer
                .get("exec")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            if let Some(blob) = pkg.members.get(file) {
                let files = det::files_from_tar(blob)?;
                let exec_refs: Vec<&str> = execs.iter().map(|s| s.as_str()).collect();
                let out = dest.join(kind);
                det::extract_tree(&files, &out, true, &exec_refs)?;
            }
        }
    }
    Ok(dest.to_path_buf())
}

// ------------------------------------------------------------------ pack

#[derive(Debug, Clone)]
pub struct PackOptions {
    pub output: Option<PathBuf>,
    pub target: Option<String>,
    pub thin: bool,
    pub progress: Option<String>,
}

pub fn load_source(source_dir: &Path) -> Result<Manifest, BlackboxError> {
    let mpath = source_dir.join(MANIFEST_NAME);
    if !mpath.is_file() {
        return Err(BlackboxError::new(format!("No {} found in {}", MANIFEST_NAME, source_dir.display()))
            .with_detail("A BLACKBOX project directory must contain a blackbox.yaml manifest.")
            .with_try("blackbox init myproject   # creates a starter project"));
    }
    let text = std::fs::read_to_string(&mpath).map_err(|e| {
        BlackboxError::new(format!("Could not read {}", mpath.display())).with_detail(e.to_string())
    })?;
    load_manifest(&text).map_err(|e| e.into())
}

#[derive(Debug, Clone)]
pub struct PackOutput {
    pub path: PathBuf,
    pub manifest_name: String,
    pub bytes: u64,
}

pub fn pack(source_dir: &Path, opts: &PackOptions) -> Result<PackOutput, BlackboxError> {
    let source_dir = path_abs(source_dir);
    let mut manifest = load_source(&source_dir)?;
    if let Some(target) = &opts.target {
        if crate::platform::target_info(target).is_err() {
            return Err(BlackboxError::new(format!("Unknown target '{}'.", target)));
        }
        if !manifest.runtime.targets.is_empty() {
            return Err(BlackboxError::new(
                "Cannot use --target with a manifest that declares runtime.targets.",
            ));
        }
        manifest.runtime.target = target.clone();
        manifest.runtime.targets = vec![target.clone()];
    }

    let cas = CAS::default();
    let say = |s: &str| {
        if let Some(p) = &opts.progress {
            println!("  {}", s);
            let _ = p;
        }
    };

    let rtype = manifest.runtime.rtype.clone();
    let targets: Vec<String> = if manifest.runtime.targets.is_empty() {
        vec![manifest.runtime.target.clone()]
    } else {
        manifest.runtime.targets.clone()
    };

    say(&format!(
        "resolving dependencies for {} ({} {})...",
        manifest.name, rtype, manifest.runtime.version
    ));

    // app layer: collected once - shared by every target
    let extra = format!("{}-work", manifest.name);
    let excludes: Vec<&str> = {
        let mut v: Vec<&str> = EXCLUDE_AT_PACK.to_vec();
        v.push(extra.as_str());
        v
    };
    let (app_files, app_execs) = det::collect_tree(&source_dir, &excludes)
        .map_err(|e| BlackboxError::new("Could not collect application tree").with_detail(e.to_string()))?;
    let app_blob = det::tar_from_files(&app_files, &app_execs.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .map_err(|e| BlackboxError::new("Could not build application layer").with_detail(e.to_string()))?;
    let app_digest = format!("sha256:{}", det::sha256_bytes(&app_blob));

    // per-target dependency layers
    let mut layers_json_array: Vec<Value> = Vec::new();
    let mut extra_members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut lock_value: Value = Value::Null;

    for target in &targets {
        let lock = crate::dependency::build_lock_for_target(&source_dir, &mut manifest, target)?;
        lock_value = lock.clone();
        let mut deps_blob: Option<Vec<u8>> = None;
        let mut deps_execs: Vec<String> = Vec::new();
        match rtype.as_str() {
            "python" => {
                let packages = lock.get("packages").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
                if packages > 0 {
                    say("fetching locked package(s)...");
                    let wheels_dir = crate::dependency::fetch_locked(&lock, &cas)?;
                    let site_files = crate::dependency::build_site_packages(&lock, &wheels_dir)?;
                    deps_blob = Some(det::tar_from_files(&site_files, &[])
                        .map_err(|e| BlackboxError::new("Could not build dependency layer").with_detail(e.to_string()))?);
                }
            }
            "node" => {
                say("installing npm dependencies...");
                let (site_files, execs) = crate::dependency::node_site_files(&source_dir, &lock)?;
                if !site_files.is_empty() {
                    let exec_refs: Vec<&str> = execs.iter().map(|s| s.as_str()).collect();
                    deps_blob = Some(det::tar_from_files(&site_files, &exec_refs)
                        .map_err(|e| BlackboxError::new("Could not build node_modules layer").with_detail(e.to_string()))?);
                    deps_execs = execs;
                }
            }
            _ => {}
        }

        let mut app_entry = serde_json::json!({
            "kind": "application",
            "digest": app_digest,
            "file": APP_LAYER,
            "members": app_files.len(),
            "bytes": app_blob.len(),
            "exec": app_execs,
        });
        if targets.len() > 1 {
            app_entry.as_object_mut().unwrap().insert("target".into(), Value::String(target.clone()));
        }

        if let Some(dep_blob) = deps_blob {
            let dep_digest = format!("sha256:{}", det::sha256_bytes(&dep_blob));
            let member_name = if targets.len() > 1 {
                format!("dependencies-{}.tar.zst", target)
            } else {
                DEPS_LAYER.to_string()
            };
            extra_members.insert(member_name.clone(), dep_blob.clone());
            let mut entry = serde_json::json!({
                "kind": "dependencies",
                "digest": dep_digest,
                "file": member_name,
                "members": 0,
                "bytes": dep_blob.len(),
                "exec": deps_execs,
            });
            if targets.len() > 1 {
                entry.as_object_mut().unwrap().insert("target".into(), Value::String(target.clone()));
            }
            layers_json_array.push(entry);
        }
        layers_json_array.push(app_entry);
    }

    say("assembling package...");
    let mut members = BTreeMap::new();
    let manifest_value = serde_json::to_value(&manifest).map_err(|e| BlackboxError::new("Could not serialize manifest").with_detail(e.to_string()))?;
    members.insert(MANIFEST.to_string(), det::canon_json(&det::json_sorted(&manifest_value)));
    if !lock_value.is_null() {
        members.insert(LOCK.to_string(), yaml_sorted_str(&lock_value).into_bytes());
    }
    members.insert(APP_LAYER.to_string(), app_blob.clone());
    for (k, v) in &extra_members {
        members.insert(k.clone(), v.clone());
    }
    members.insert(
        LAYERS_INDEX.to_string(),
        det::canon_json(&serde_json::json!({"layers": layers_json_array})),
    );
    members.insert(
        PROVENANCE.to_string(),
        det::canon_json(&serde_json::json!({
            "tool": format!("blackbox {}", crate::VERSION),
            "host": crate::platform::current_triple(),
            "target": manifest.runtime.target,
            "runtime": {"type": manifest.runtime.rtype, "version": manifest.runtime.version},
            "layers": layers_json_array.iter().map(|l| l.get("digest").and_then(|v| v.as_str()).unwrap_or("").to_string()).collect::<Vec<_>>(),
            "thin": opts.thin,
        })),
    );

    if !opts.thin {
        let _ = cas.put_bytes(&app_blob);
        for (_, v) in &extra_members {
            let _ = cas.put_bytes(v);
        }
    } else {
        // thin: only the manifest/lock/index ride along in the FILE; the layer
        // blobs stay in the local CAS (and can be fetched back from mirrors by
        // `blackbox fetch`) so a same-machine run needs no network either.
        let _ = cas.put_bytes(&app_blob);
        for (_, v) in &extra_members {
            let _ = cas.put_bytes(v);
        }
        members.remove(APP_LAYER);
        for k in extra_members.keys() {
            members.remove(k);
        }
        if let Some(index) = members.get_mut(LAYERS_INDEX) {
            *index = det::canon_json(&serde_json::json!({
                "layers": layers_json_array,
                "sources": crate::storage::object_sources(),
            }));
        }
    }

    // encrypted packages keep secrets.json inside encrypted.json; secret
    // sealing with `blackbox seal` happens after pack (in commands.rs)

    let zip_bytes = write_deterministic_zip(&members, true)?;
    let out_path = opts
        .output
        .clone()
        .or_else(|| {
            // default: <source>/<name>.blackbox
            Some(
                source_dir.join(format!("{}.blackbox", manifest.name)),
            )
        })
        .ok_or_else(|| BlackboxError::new("Could not determine the package output path."))?;
    let out_path = if out_path.is_dir() {
        out_path.join(format!("{}.blackbox", manifest.name))
    } else {
        out_path
    };
    std::fs::write(&out_path, &zip_bytes)
        .map_err(|e| BlackboxError::new(format!("Could not write {}", out_path.display())).with_detail(e.to_string()))?;
    say(&format!("wrote {} ({})", out_path.display(), det::human_size(zip_bytes.len() as u64)));
    Ok(PackOutput {
        path: out_path.clone(),
        manifest_name: manifest.name.clone(),
        bytes: zip_bytes.len() as u64,
    })
}

fn path_abs(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    }
}

// ------------------------------------------------------- secrets + signing

pub fn seal_secrets_into_packages(pkg_path: &Path, secrets_file: &Path, to_pub_pem: &Path) -> Result<PathBuf, BlackboxError> {
    let pkg = open_package(pkg_path)?;
    let mut members = pkg.members.clone();
    let pubpem = std::fs::read(to_pub_pem).map_err(|e| {
        BlackboxError::new(format!("Could not read {}", to_pub_pem.display())).with_detail(e.to_string())
    })?;
    let lines: Vec<String> = std::fs::read_to_string(secrets_file)
        .map_err(|e| BlackboxError::new("Could not read the secrets file").with_detail(e.to_string()))?
        .lines()
        .map(|l| l.to_string())
        .collect();
    let payload = lines.join("\n").into_bytes();
    let blob = crate::crypto::seal_bytes(&payload, &pubpem)?;
    members.insert(SECRETS.to_string(), blob);
    let zip_bytes = write_deterministic_zip(&members, true)?;
    std::fs::write(pkg_path, &zip_bytes)
        .map_err(|e| BlackboxError::new("Could not write the sealed package").with_detail(e.to_string()))?;
    Ok(pkg_path.to_path_buf())
}

pub fn sign_package(pkg_path: &Path, key_name: &str) -> Result<PathBuf, BlackboxError> {
    let pkg = open_package(pkg_path)?;
    let kd = crate::crypto::keys_dir();
    let priv_pem = kd.join(format!("{}.key.pem", key_name));
    if !priv_pem.is_file() {
        return Err(BlackboxError::new(format!("No signing key '{}'.", key_name))
            .with_try("blackbox keygen <name>   then   blackbox sign pkg --key <name>"));
    }
    let signing_key = crate::crypto::load_ed25519_private(&priv_pem)?;
    let vk = signing_key.verifying_key();
    let pub_pem = crate::crypto::public_key_pem(&vk);
    let mut publisher = key_name.to_string();
    let meta_path = kd.join(format!("{}.meta.json", key_name));
    if meta_path.is_file() {
        if let Ok(v) = serde_json::from_slice::<Value>(&std::fs::read(&meta_path).unwrap_or_default()) {
            publisher = v.get("publisher").and_then(|p| p.as_str()).unwrap_or(key_name).to_string();
        }
    }
    let signature = crate::crypto::sign_bytes(&signing_key, pkg.content_digest().as_bytes());
    let signature_json = det::canon_json(&serde_json::json!({
        "alg": "ed25519",
        "publisher": publisher,
        "public_key": pub_pem,
        "signature": hex::encode(&signature),
        "content_digest": pkg.content_digest(),
    }));
    let mut members = pkg.members.clone();
    members.insert(SIGNATURE.to_string(), signature_json);
    let zip_bytes = write_deterministic_zip(&members, true)?;
    std::fs::write(pkg_path, &zip_bytes)
        .map_err(|e| BlackboxError::new("Could not write the signed package").with_detail(e.to_string()))?;
    Ok(pkg_path.to_path_buf())
}

// ------------------------------------------------------------- composite

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompositeStage {
    pub name: String,
    pub package: String,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CompositeManifest {
    pub format_version: String,
    pub kind: String,
    pub name: String,
    pub stages: Vec<CompositeStage>,
}

/// Build a composite .blackbox: `stages/<NN>-<name>.blackbox` members +
/// `stages.json` listing + a synthesized manifest.json.
pub fn build_composite(compose: &CompositeManifest, base_dir: &Path, out_path: &Path) -> Result<PathBuf, BlackboxError> {
    let mut members = BTreeMap::new();
    let mut stage_json = Vec::new();
    for (i, stage) in compose.stages.iter().enumerate() {
        let stage_path = resolve_relative(base_dir, &stage.package);
        let name = format!("{:02}-{}.blackbox", i, stage.name);
        let blob = std::fs::read(&stage_path)
            .map_err(|e| BlackboxError::new(format!("Could not read stage package '{}'", stage.package)).with_detail(e.to_string()))?;
        members.insert(format!("{}", stage_member_name(&name)), blob.clone());
        stage_json.push(serde_json::json!({
            "name": stage.name,
            "member": stage_member_name(&name),
            "args": stage.args,
            "digest": format!("sha256:{}", det::sha256_bytes(&blob)),
        }));
    }
    let name = compose.name.clone();
    let manifest_value = serde_json::json!({
        "format_version": "1",
        "name": name,
        "version": "0.1.0",
        "description": format!("Composite pipeline '{}'", compose.name),
        "publisher": "Unknown",
        "runtime": {"type": "composite", "version": "1", "target": crate::platform::current_triple()},
        "entrypoint": {"command": "compose", "args": []},
        "permissions": {"filesystem": {"read": [], "write": ["./output"]}, "network": {"enabled": false, "allow": []}, "process": {"spawn": false}},
        "limits": {},
        "entrypoints": {},
        "environment": {"variables": {}},
        "interface": {"type": "cli", "port": null},
    });
    members.insert(MANIFEST.to_string(), det::canon_json(&det::json_sorted(&manifest_value)));
    members.insert(STAGES.to_string(), det::canon_json(&serde_json::json!({"stages": stage_json})));
    let zip_bytes = write_deterministic_zip(&members, true)?;
    std::fs::write(out_path, &zip_bytes)
        .map_err(|e| BlackboxError::new(format!("Could not write {}", out_path.display())).with_detail(e.to_string()))?;
    Ok(out_path.to_path_buf())
}

fn stage_member_name(name: &str) -> String {
    format!("stages/{}", name)
}

fn resolve_relative(base: &Path, p: &str) -> PathBuf {
    let pb = PathBuf::from(p);
    if pb.is_absolute() {
        pb
    } else {
        base.join(pb)
    }
}

pub fn prepare_run(pkg: &Package, work_dir: &Path, data_dir: Option<&Path>) -> Result<RunContext, BlackboxError> {
    let m = &pkg.manifest;
    let rt = &m.runtime;
    let provider = crate::runtime::providers::get_provider(&rt.rtype)?;
    let lock_text = String::from_utf8_lossy(pkg.members.get(LOCK).map(|v| v.as_slice()).unwrap_or(b"{}"));
    let lock_value: Value = serde_yaml::from_str(&lock_text)
        .map(|v: serde_yaml::Value| serde_json::to_value(v).unwrap_or(Value::Null))
        .unwrap_or_else(|_| {
            serde_json::from_str(&lock_text).unwrap_or(Value::Null)
        });
    let pin: Option<Value> = lock_value
        .get("runtime")
        .filter(|v| !v.is_null())
        .cloned();
    let runtime_exe = provider.ensure(&rt.version, &rt.target, pin.as_ref())?;
    let dirs = install(pkg, &CAS::default(), false)?;
    let app_dir = dirs.get("application_dir").cloned().flatten().ok_or_else(|| {
        BlackboxError::new("Package has no application layer for this platform.")
            .with_try("This is likely a multi-target package built for another platform.")
    })?;
    let site_dir = dirs.get("site_dir").cloned().flatten().unwrap_or_default();
    let mut ctx = RunContext::new(
        m,
        &app_dir,
        &site_dir,
        runtime_exe.as_deref(),
        work_dir,
        &rt.target,
    );
    if let Some(d) = data_dir {
        ctx.data_dir = Some(d.to_path_buf());
    }
    if let Some(sealed) = pkg.members.get(SECRETS) {
        match crate::crypto::open_sealed(sealed) {
            Ok(map) => ctx.secrets = Some(map),
            Err(e) => {
                ctx.sealed_error = Some(e.summary.clone());
            }
        }
    }
    Ok(ctx)
}

pub fn summarize_layers(pkg: &Package) -> String {
    let mut out = String::new();
    if let Some(idx) = pkg.members.get(LAYERS_INDEX) {
        if let Ok(v) = serde_json::from_slice::<Value>(idx) {
            if let Some(layers) = v.get("layers").and_then(|l| l.as_array()) {
                for layer in layers {
                    let kind = layer.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
                    let digest = layer.get("digest").and_then(|k| k.as_str()).unwrap_or("");
                    let bytes = layer.get("bytes").and_then(|k| k.as_u64()).unwrap_or(0);
                    let target = layer.get("target").and_then(|k| k.as_str()).unwrap_or("any");
                    out.push_str(&format!(
                        "  {:<13} {} {:>8} B  {} {}\n",
                        kind,
                        &digest[..digest.len().min(19)],
                        bytes,
                        if target == "any" { "any target".to_string() } else { format!("target: {}", target) },
                        ""
                    ));
                }
            }
        }
    }
    out
}

pub fn read_all(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, PackageFormatError> {
    read_zip_all(path)
}
