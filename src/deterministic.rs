//! Deterministic primitives: hashing, canonical JSON, reproducible tar/zip.
//!
//! Same inputs -> same bytes is a product requirement (see docs/format.md).
//! Everything here avoids timestamps, OS metadata, and dictionary ordering.

use crate::error::PackageFormatError;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::Path;

/// Fixed epoch for all archive members: 1980-01-01 (ZIP minimum).
pub const FIXED_MTIME: u64 = 315532800;
pub const FIXED_YEAR: u16 = 1980;
pub const FIXED_MONTH: u8 = 1;
pub const FIXED_DAY: u8 = 1;

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

pub struct Hasher {
    inner: Sha256,
}

impl Hasher {
    pub fn new() -> Self {
        Hasher { inner: Sha256::new() }
    }
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    pub fn finish(self) -> String {
        hex::encode(self.inner.finalize())
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

fn escape_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if cp < 0x20 || c == '"' || c == '\\' {
            out.push(c);
        } else if cp < 0x80 {
            out.push(c);
        } else {
            out.push_str(&format!("\\u{:04x}", cp));
        }
    }
    out
}

/// Canonical JSON: sorted keys, tight separators, UTF-8, ASCII-escaped
/// (serde_json already emits compact + sorted keys via BTreeMap Maps; this
/// wrapper emulates Python's `ensure_ascii=True` for byte-parity).
pub fn canon_json(value: &Value) -> Vec<u8> {
    let s = serde_json::to_string(value).unwrap_or_default();
    // serde_json does not escape non-ASCII; do it to match the format spec
    if s.is_ascii() {
        s.into_bytes()
    } else {
        // Escape only non-ASCII chars outside of strings would be wrong, but
        // serde's output escapes everything structural; only string content
        // may hold non-ASCII. A full re-escape pass over string literals is
        // cheap enough at pack time.
        escape_strings(&s).into_bytes()
    }
}

fn escape_strings(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    let mut in_string = false;
    let chars: Vec<char> = json.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if !in_string {
            out.push(c);
            if c == '"' {
                in_string = true;
            }
            i += 1;
        } else if c == '\\' {
            out.push(c);
            if i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
            } else {
                i += 1;
            }
        } else if c == '"' {
            in_string = false;
            out.push(c);
            i += 1;
        } else {
            let cp = c as u32;
            if cp >= 0x80 {
                out.push_str(&format!("\\u{:04x}", cp));
            } else {
                out.push(c);
            }
            i += 1;
        }
    }
    out
}

pub fn zstd_compress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    zstd::stream::encode_all(Cursor::new(&data[..]), 3)
}

pub fn zstd_decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    zstd::stream::decode_all(Cursor::new(&data[..]))
}

/// Deterministic zstd-compressed tar from {arcname: bytes} (plus "dir/" keys -> None).
/// `exec_paths` marks files that get mode 0755. Long paths use GNU long-name
/// extensions (required for node_modules trees); every archive field is fixed.
pub fn tar_from_files(files: &BTreeMap<String, Option<Vec<u8>>>, exec_paths: &[&str]) -> std::io::Result<Vec<u8>> {
    let mut out = Cursor::new(Vec::new());
    {
        let enc = zstd::stream::write::Encoder::new(&mut out, 3)?;
        let mut builder = tar::Builder::new(enc);
        builder.mode(tar::HeaderMode::Deterministic);
        for (name, data) in files {
            let is_dir = name.ends_with('/') || data.is_none();
            let rel = name.trim_end_matches('/');
            let mut h = tar::Header::new_gnu();
            h.set_entry_type(if is_dir { tar::EntryType::Directory } else { tar::EntryType::Regular });
            h.set_mode(if is_dir {
                0o755
            } else if exec_paths.iter().any(|e| *e == rel) {
                0o755
            } else {
                0o644
            });
            h.set_uid(0);
            h.set_gid(0);
            h.set_mtime(FIXED_MTIME);
            h.set_username("");
            h.set_groupname("");
            let payload: Cursor<Vec<u8>> = if is_dir {
                Cursor::new(Vec::new())
            } else {
                Cursor::new(data.clone().unwrap_or_default())
            };
            h.set_size(if is_dir { 0 } else { payload.get_ref().len() as u64 });
            builder.append_data(&mut h, rel, payload)?;
        }
        let enc = builder.into_inner()?;
        enc.finish()?;
    }
    Ok(out.into_inner())
}

/// Inverse of `tar_from_files`: {arcname: bytes} (dirs as None, keys with '/').
pub fn files_from_tar(blob: &[u8]) -> Result<BTreeMap<String, Option<Vec<u8>>>, PackageFormatError> {
    let decompressed = zstd_decompress(blob)
        .map_err(|e| PackageFormatError::new("Layer blob is not valid zstd data")
            .with_detail(e.to_string()))?;
    let mut dec = tar::Archive::new(Cursor::new(decompressed));
    let mut out = BTreeMap::new();
    let mut entries = dec
        .entries()
        .map_err(|e| PackageFormatError::new("Layer blob is not a readable tar archive").with_detail(e.to_string()))?;
    while let Some(entry) = entries
        .next()
        .transpose()
        .map_err(|e| PackageFormatError::new("Layer tar stream is malformed").with_detail(e.to_string()))?
    {
        let entry = entry;
        let name = entry
            .path()
            .map_err(|e| PackageFormatError::new("Layer tar entry has an invalid path").with_detail(e.to_string()))?
            .to_string_lossy()
            .replace('\\', "/");
        let etype = entry.header().entry_type();
        if etype.is_dir() {
            out.insert(name.trim_end_matches('/').to_string() + "/", None);
        } else         if etype.is_file() || etype == tar::EntryType::Regular || etype == tar::EntryType::Continuous || etype.is_symlink() {
            let mut data = Vec::new();
            let size = entry.header().size().unwrap_or(0);
            let mut limited = entry.take(size);
            limited
                .read_to_end(&mut data)
                .map_err(|e| PackageFormatError::new(format!("Could not read tar member '{}'", name)).with_detail(e.to_string()))?;
            out.insert(name, Some(data));
        }
    }
    Ok(out)
}

pub fn is_junk(name: &str) -> bool {
    name == "__pycache__"
        || name == ".DS_Store"
        || name.ends_with(".pyc")
        || name.ends_with(".pyo")
        || name.ends_with(".blackbox")
        || name.starts_with(".blackbox-tmp")
        || name.ends_with(".staging")
}

/// Collect ({relpath: bytes}, sorted exec paths) under root, skipping junk/excluded.
pub fn collect_tree(root: &Path, exclude: &[&str]) -> std::io::Result<(BTreeMap<String, Option<Vec<u8>>>, Vec<String>)> {
    let mut files = BTreeMap::new();
    let mut execs: Vec<String> = Vec::new();
    let root_abs = std::env::current_dir()?.join(root);
    let root_abs = if root_abs.is_absolute() {
        root_abs
    } else {
        root_abs.canonicalize().unwrap_or(root_abs)
    };
    let walker = walkdir::WalkDir::new(&root_abs).sort_by_file_name();
    for entry in walker.into_iter().filter_entry(|e| {
        if e.depth() == 0 {
            return true;
        }
        let name = e.file_name().to_string_lossy().to_string();
        if e.file_type().is_dir() {
            !is_excluded(&name, exclude) && !is_junk(&name)
        } else {
            let tp = e.file_type();
            if tp.is_file() || tp.is_symlink() {
                !is_junk(&name) && !is_excluded_file(e.path(), &root_abs, exclude)
            } else {
                false
            }
        }
    }) {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        if entry.depth() == 0 {
            continue;
        }
        if entry.file_type().is_dir() {
            let rel = entry
                .path()
                .strip_prefix(&root_abs)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            files.insert(format!("{}/", rel), None);
        } else {
            let rel = entry
                .path()
                .strip_prefix(&root_abs)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if let Ok(data) = std::fs::read(entry.path()) {
                if crate::platform::exec_bit_set(entry.path()) {
                    execs.push(rel.clone());
                }
                files.insert(rel, Some(data));
            }
        }
    }
    files.retain(|name, _| {
        if name.ends_with('/') {
            return true;
        }
        !is_junk(name)
    });
    Ok((files, execs))
}

fn is_excluded(name: &str, exclude: &[&str]) -> bool {
    exclude.iter().any(|e| {
        let e = e.trim_end_matches('/');
        name == e
    })
}

fn is_excluded_file(path: &Path, root: &Path, exclude: &[&str]) -> bool {
    let rel = path
        .strip_prefix(root)
        .map(|p| p.to_string_lossy().replace('\\', "/").to_string())
        .unwrap_or_default();
    exclude.iter().any(|e| {
        let e = e.trim_end_matches('/');
        rel == e || rel.starts_with(&format!("{}/", e))
    }) || rel.ends_with("/blackbox.lock")
}

/// Extract a file map under dest_root, staging atomically. Traversal is
/// rejected. Returns true when the tree was materialized.
pub fn extract_tree(
    files: &BTreeMap<String, Option<Vec<u8>>>,
    dest_root: &Path,
    overwrite: bool,
    exec_paths: &[&str],
) -> Result<bool, PackageFormatError> {
    let dest_root = std::env::current_dir().unwrap_or_default().join(dest_root);
    if dest_root.exists() && !overwrite {
        return Ok(false);
    }
    let parent = dest_root
        .parent()
        .ok_or_else(|| PackageFormatError::new("Invalid destination path"))?;
    let staged = parent.join(format!(
        "{}.blackbox-tmp",
        dest_root
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default()
    ));
    if staged.exists() {
        let _ = std::fs::remove_dir_all(&staged);
    }
    std::fs::create_dir_all(&staged).map_err(|e| PackageFormatError::new("Could not stage layer extraction").with_detail(e.to_string()))?;
    let staged_abs = staged
        .canonicalize()
        .map_err(|e| PackageFormatError::new("Could not resolve staged dir").with_detail(e.to_string()))?;
    for (name, data) in files {
        let rel = name.trim_end_matches('/');
        let mut target = staged.join(rel);
        for comp in rel.split('/') {
            if comp == ".." || comp.is_empty() {
                return Err(PackageFormatError::new(format!("Refusing unsafe path in package: {}", name)));
            }
        }
        if name.ends_with('/') {
            std::fs::create_dir_all(&target).map_err(|e| {
                PackageFormatError::new(format!("Could not create directory '{}'", name)).with_detail(e.to_string())
            })?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                PackageFormatError::new(format!("Could not create parent of '{}'", name)).with_detail(e.to_string())
            })?;
        }
        if let Some(payload) = data {
            std::fs::write(&target, payload).map_err(|e| {
                PackageFormatError::new(format!("Could not write '{}'", name)).with_detail(e.to_string())
            })?;
        }
        if exec_paths.iter().any(|e| *e == rel) {
            let _ = crate::platform::set_exec_bit(&target);
        }
        // re-validate final path stays inside staged dir
        let canonical = target.canonicalize().unwrap_or_else(|_| target.clone());
        if !canonical.starts_with(&staged_abs) {
            return Err(PackageFormatError::new(format!("Refusing unsafe path in package: {}", name)));
        }
    }
    if dest_root.exists() {
        std::fs::remove_dir_all(&dest_root).map_err(|e| {
            PackageFormatError::new("Could not replace existing extraction target").with_detail(e.to_string())
        })?;
    }
    std::fs::rename(&staged, &dest_root).map_err(|e| {
        PackageFormatError::new("Could not finalize layer extraction").with_detail(e.to_string())
    })?;
    Ok(true)
}

pub fn human_size(n: u64) -> String {
    let mut size = n as f64;
    for unit in ["B", "KB", "MB", "GB"] {
        if size < 1024.0 || unit == "GB" {
            return if unit == "B" {
                format!("{} B", n)
            } else {
                format!("{:.1} {}", size, unit)
            };
        }
        size /= 1024.0;
    }
    format!("{} B", n)
}

#[allow(dead_code)]
pub fn json_sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.clone(), json_sorted(v));
            }
            Value::Object(
                sorted
                    .into_iter()
                    .map(|(k, v)| (k, v))
                    .collect::<serde_json::Map<String, Value>>(),
            )
        }
        Value::Array(arr) => Value::Array(arr.iter().map(json_sorted).collect()),
        other => other.clone(),
    }
}
