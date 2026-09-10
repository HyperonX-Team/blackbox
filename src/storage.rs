//! BLACKBOX home directory layout and the content-addressed object store.
//!
//! Objects are immutable and addressed by sha256 digest:
//! objects/sha256/<aa>/<full-hash>. Deduplication is the whole point:
//! identical layers (runtimes, dependency bundles, application trees) are
//! stored exactly once regardless of how many packages use them.

use crate::deterministic;
use crate::error::IntegrityError;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn home() -> PathBuf {
    if let Ok(override_home) = std::env::var("BLACKBOX_HOME") {
        return PathBuf::from(override_home);
    }
    if let Some(home_dir) = std::env::var_os("HOME") {
        return PathBuf::from(home_dir).join(".blackbox");
    }
    if let Some(home_dir) = std::env::var_os("USERPROFILE") {
        return PathBuf::from(home_dir).join(".blackbox");
    }
    std::env::current_dir().unwrap_or_default().join(".blackbox")
}

#[derive(Debug, Clone)]
pub struct HomeLayout {
    pub root: PathBuf,
    pub objects: PathBuf,
    pub runtimes: PathBuf,
    pub packages: PathBuf,
    pub tmp: PathBuf,
    pub logs: PathBuf,
    pub keys: PathBuf,
    pub layers: PathBuf,
    pub shim: PathBuf,
    pub services: PathBuf,
}

pub fn ensure_home() -> HomeLayout {
    let h = home();
    let layout = HomeLayout {
        root: h.clone(),
        objects: h.join("objects"),
        runtimes: h.join("runtimes"),
        packages: h.join("packages"),
        tmp: h.join("tmp"),
        logs: h.join("logs"),
        keys: h.join("keys"),
        layers: h.join("layers"),
        shim: h.join("sandbox-shim"),
        services: h.join("services"),
    };
    for d in [
        &layout.root,
        &layout.objects,
        &layout.runtimes,
        &layout.packages,
        &layout.tmp,
        &layout.logs,
        &layout.keys,
        &layout.layers,
        &layout.shim,
        &layout.services,
    ] {
        let _ = std::fs::create_dir_all(d);
    }
    layout
}

pub fn index_path() -> PathBuf {
    home().join("packages").join("index.json")
}

pub fn load_index() -> BTreeMap<String, String> {
    let p = index_path();
    if !p.exists() {
        return BTreeMap::new();
    }
    serde_json::from_str(&std::fs::read_to_string(p).unwrap_or_default()).unwrap_or_default()
}

pub fn save_index(idx: &BTreeMap<String, String>) {
    let p = index_path();
    let _ = std::fs::create_dir_all(p.parent().unwrap());
    let tmp = p.with_extension("json.tmp");
    let data = serde_json::to_string_pretty(idx).unwrap_or_default();
    let _ = std::fs::write(&tmp, data);
    let _ = std::fs::rename(&tmp, p);
}

/// Object fetchers for thin packages: a list of base URLs under which a
/// mirror exposes objects by digest, e.g. `http://10.0.0.5:8787/objects/`.
pub fn object_sources() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(env_srcs) = std::env::var("BLACKBOX_OBJECT_URLS") {
        for s in env_srcs.split([',', ' ']).filter(|s| !s.is_empty()) {
            out.push(s.trim_end_matches('/').to_string());
        }
    }
    out
}

#[derive(Debug, Clone)]
pub struct CAS {
    pub root: PathBuf,
}

impl Default for CAS {
    fn default() -> Self {
        Self::new(None)
    }
}

impl CAS {
    pub fn new(root: Option<PathBuf>) -> Self {
        let root = root
            .map(|r| r.canonicalize().unwrap_or(r))
            .unwrap_or_else(|| home().join("objects"));
        CAS { root }
    }

    pub fn object_path(&self, digest_hex: &str) -> PathBuf {
        self.root
            .join("sha256")
            .join(&digest_hex[..2])
            .join(digest_hex)
    }

    pub fn has(&self, ref_str: &str) -> bool {
        match Self::parse(ref_str) {
            Ok(hex) => self.object_path(&hex).is_file(),
            Err(_) => false,
        }
    }

    pub fn put_bytes(&self, data: &[u8]) -> Result<String, IntegrityError> {
        let digest = deterministic::sha256_bytes(data);
        let dest = self.object_path(&digest);
        if dest.is_file() {
            return Ok(format!("sha256:{}", digest));
        }
        let parent = dest
            .parent()
            .ok_or_else(|| IntegrityError::new("Invalid CAS destination"))?;
        std::fs::create_dir_all(parent).map_err(|e| IntegrityError::new("Could not create CAS dir").with_detail(e.to_string()))?;
        let tmp = self
            .root
            .join(format!(".put-{}-{}{}", digest, std::process::id(), rand::random::<u64>()));
        std::fs::write(&tmp, data).map_err(|e| IntegrityError::new("Could not write CAS object").with_detail(e.to_string()))?;
        match std::fs::rename(&tmp, &dest) {
            Ok(()) => {}
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                if !dest.is_file() {
                    return Err(IntegrityError::new("Could not finalize CAS object").with_detail(e.to_string()));
                }
            }
        }
        Ok(format!("sha256:{}", digest))
    }

    pub fn put_file(&self, src: &Path) -> Result<String, IntegrityError> {
        let data =
            std::fs::read(src).map_err(|e| IntegrityError::new(format!("Could not read {}", src.display())).with_detail(e.to_string()))?;
        self.put_bytes(&data)
    }

    pub fn get_path(&self, ref_str: &str) -> Result<PathBuf, IntegrityError> {
        let hex = Self::parse(ref_str).map_err(|_| {
            IntegrityError::new(format!("Malformed object reference: \"{}\"", ref_str))
        })?;
        let p = self.object_path(&hex);
        if !p.is_file() {
            // NEW: content mirrors. The CAS can fetch objects by digest from
            // configured sources instead of failing - this is what makes a
            // thin .blackbox runnable with `blackbox fetch --mirror ...`.
            if let Ok(data) = self.fetch_from_mirrors(&hex) {
                if deterministic::sha256_bytes(&data) == hex {
                    let parent = self.object_path(&hex);
                    if let Some(parent_dir) = parent.parent() {
                        let _ = std::fs::create_dir_all(parent_dir);
                    }
                    let tmp = self.root.join(format!(".fetch-{}-{}", std::process::id(), rand::random::<u64>()));
                    if std::fs::write(&tmp, &data).is_ok() {
                        let moved = std::fs::rename(&tmp, &parent);
                        if moved.is_err() {
                            let _ = std::fs::remove_file(&tmp);
                        }
                        return Ok(parent);
                    }
                }
            }
            return Err(IntegrityError::new("Cached object is missing from the local store.")
                .with_detail(format!("Requested: {}\nAttempted: {}", ref_str, p.display()))
                .with_try(
                    "blackbox fetch <package> --mirror <url>   (or BLACKBOX_OBJECT_URLS)\nblackbox cache --clear  (then re-run)",
                ));
        }
        Ok(p)
    }

    pub fn fetch_from_mirrors(&self, dig_hex: &str) -> Result<Vec<u8>, IntegrityError> {
        for src in object_sources() {
            let url = format!("{}/{}", src.trim_end_matches('/'), dig_hex);
            if let Ok(data) = crate::serve::http_get(&url) {
                if deterministic::sha256_bytes(&data) == dig_hex {
                    return Ok(data);
                }
            }
        }
        Err(IntegrityError::new("Object could not be fetched from any configured mirror."))
    }

    pub fn verify(&self, ref_str: &str) -> bool {
        match Self::parse(ref_str) {
            Ok(hex) => {
                let p = self.object_path(&hex);
                if !p.is_file() {
                    return false;
                }
                deterministic::sha256_file(&p)
                    .map(|actual| actual == hex)
                    .unwrap_or(false)
            }
            Err(_) => false,
        }
    }

    pub fn delete(&self, ref_str: &str) {
        if let Ok(hex) = Self::parse(ref_str) {
            let _ = std::fs::remove_file(self.object_path(&hex));
        }
    }

    pub fn parse(ref_str: &str) -> Result<String, ()> {
        if let Some(hex) = ref_str.strip_prefix("sha256:") {
            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(hex.to_string());
            }
        }
        Err(())
    }

    pub fn stats(&self) -> Result<BTreeMap<String, i64>, std::io::Error> {
        let mut objs = 0i64;
        let mut bytes = 0i64;
        let base = self.root.join("sha256");
        if base.is_dir() {
            for entry in walkdir::WalkDir::new(&base) {
                if let Ok(e) = entry {
                    if e.file_type().is_file() {
                        objs += 1;
                        bytes += e.metadata().map(|m| m.len() as i64).unwrap_or(0);
                    }
                }
            }
        }
        let mut out = BTreeMap::new();
        out.insert("objects".into(), objs);
        out.insert("bytes".into(), bytes);
        out.insert("root".into(), 0);
        Ok(out)
    }

    pub fn clear(&self) {
        let base = self.root.join("sha256");
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::create_dir_all(&base);
    }

    /// Verify every stored object's digest; return list of corrupt refs.
    pub fn check_all(&self) -> Vec<String> {
        let mut corrupt = Vec::new();
        let base = self.root.join("sha256");
        if base.is_dir() {
            for entry in walkdir::WalkDir::new(&base) {
                if let Ok(e) = entry {
                    if e.file_type().is_file() {
                        let Some(name) = e.file_name().to_str().map(|s| s.to_string()) else {
                            continue;
                        };
                        if name.len() != 64 {
                            continue;
                        }
                        let actual = deterministic::sha256_file(e.path()).unwrap_or_default();
                        if actual != name {
                            corrupt.push(format!("sha256:{}", name));
                        }
                    }
                }
            }
        }
        corrupt.sort();
        corrupt
    }

    /// True if the object exists, is intact, and returning its path costs nothing.
    pub fn object_exists_and_valid(&self, ref_str: &str) -> bool {
        self.verify(ref_str)
    }
}
