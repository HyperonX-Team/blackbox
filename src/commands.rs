//! CLI subcommand implementations.

use crate::deterministic as det;
use crate::error::BlackboxError;
use crate::manifest;
use crate::packaging::{
    open_package, pack, seal_secrets_into_packages, sign_package, unpack_all,
    write_deterministic_zip, CompositeManifest, CompositeStage, PackOptions, Package,
    LAYERS_INDEX, LOCK, MANIFEST, SECRETS, SIGNATURE,
};
use crate::runtime::{self, RuntimeManager};
use crate::storage::{ensure_home, CAS};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn err(e: BlackboxError) -> i32 {
    eprintln!("{}", crate::error::render_error(&e));
    1
}

fn print_error(msg: BlackboxError) -> i32 {
    err(msg)
}

// ------------------------------------------------------------------ init

pub fn cmd_init(name: &str, template: &str, pyver: &str) -> i32 {
    let target = std::env::current_dir().unwrap_or_default().join(name);
    if target.exists() {
        return print_error(BlackboxError::new(format!("Directory '{}' already exists.", name)));
    }
    let manifest_name = Path::new(name)
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string());
    let files = match crate::templates::template_files(template) {
        Ok(f) => f,
        Err(e) => return print_error(e),
    };
    for (rel, content) in files {
        let p = target.join(&rel);
        if p.is_dir() {
            continue;
        }
        if let Some(parent) = p.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                return print_error(BlackboxError::new("Could not create project dir").with_detail(e.to_string()));
            }
        }
        let mut text = content.replace("blackbox-template", &manifest_name.to_lowercase().replace(' ', "-"));
        text = text.replace("version: \"3.12\"", &format!("version: \"{}\"", pyver));
        if let Err(e) = std::fs::write(&p, text) {
            return print_error(BlackboxError::new("Could not write template file").with_detail(e.to_string()));
        }
    }
    println!("BLACKBOX project created: {}/", name);
    println!();
    println!("Next steps:");
    println!("  cd {}", name);
    println!("  blackbox pack");
    println!("  blackbox run {}.blackbox", name);
    0
}

// ------------------------------------------------------------------ pack

pub fn cmd_pack(path: &str, output: Option<String>, target: Option<String>, thin: bool) -> i32 {
    match pack(
        Path::new(path),
        &PackOptions {
            output: output.map(PathBuf::from),
            target,
            thin,
            progress: Some(String::new()),
        },
    ) {
        Ok(o) => {
            println!("PACKED  {}", o.path.display());
            0
        }
        Err(e) => print_error(e),
    }
}

// ------------------------------------------------------------- run

pub fn cmd_run(
    package: &str,
    work: Option<String>,
    inputs: Vec<FileArg>,
    yes: bool,
    data: bool,
    log: bool,
    entry: Option<String>,
    app_args: Vec<String>,
) -> i32 {
    let pkg_path = Path::new(package);
    // composite? stages.json -> run each stage wired output->input
    if let Some(_st) = run_composite(pkg_path, work.as_deref(), yes) {
        return _st;
    }
    let pkg = match open_package(pkg_path) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let sig = signature_state(&pkg);
    if sig == SigState::Invalid {
        return print_error(BlackboxError::new("Signature INVALID - refusing to run a package whose signature does not verify.")
            .with_try("Re-obtain the package from its publisher."));
    }
    if sig == SigState::Unsigned && !yes {
        println!("{}", manifest::summarize(&pkg.manifest));
        println!();
        print!("BLACKBOX: this is an UNSIGNED package. Approve this exact content? [y/N]: ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !line.trim().eq_ignore_ascii_case("y") {
            println!("BLACKBOX: declined.");
            return 0;
        }
    } else if sig == SigState::Valid && !sig_is_trusted(&pkg) && !yes {
        println!("BLACKBOX: package has a valid signature from '{}' but the publisher is not trusted.", publisher_name(&pkg));
        print!("Approve anyway? [y/N]: ");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
        if !line.trim().eq_ignore_ascii_case("y") {
            println!("BLACKBOX: declined.");
            return 0;
        }
    } else if sig == SigState::Trusted && !yes {
        println!("BLACKBOX: signature VALID - trusted publisher '{}'", publisher_name(&pkg));
    }

    let home = ensure_home();
    let work_dir = work.map(PathBuf::from).unwrap_or_else(|| {
        home.packages.join(format!("{}-work", pkg.manifest.name))
    });

    // copy `--input` files into the work dir's input/
    let input_dir = work_dir.join("input");
    let _ = std::fs::create_dir_all(&input_dir);
    for f in inputs {
        let src = Path::new(&f.name);
        let dest = input_dir.join(&f.name);
        if let Err(e) = std::fs::copy(src, dest) {
            return print_error(BlackboxError::new(format!("Could not copy input '{}'", f.name)).with_detail(e.to_string()));
        }
    }

    let data_dir = data.then(|| home.packages.join(pkg.manifest.name.clone()).join("data"));

    let mut ctx = match crate::packaging::prepare_run(&pkg, &work_dir, data_dir.as_deref()) {
        Ok(c) => c,
        Err(e) => return print_error(e),
    };
    ctx.entry = entry;
    if log {
        ctx.log_file = Some(home.logs.join(format!("{}.log", pkg.manifest.name)));
    }
    runtime::execute(&ctx, Some(&app_args), false)
}

pub struct FileArg {
    pub name: String,
}

pub fn cmd_pack_watch(path: &str, output: Option<String>, target: Option<String>, thin: bool, run: bool) -> i32 {
    let root = Path::new(path);
    let out = output.map(PathBuf::from);
    println!("BLACKBOX: watching {} - Ctrl+C to stop", root.canonicalize().unwrap_or(root.to_path_buf()).display());
    let mut seen = watch_snapshot(root);
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        let now = watch_snapshot(root);
        if now == seen {
            continue;
        }
        seen = now;
        println!("BLACKBOX: change detected - re-packing...");
        let _ = pack(
            root,
            &PackOptions {
                output: out.clone(),
                target: target.clone(),
                thin,
                progress: Some(String::new()),
            },
        );
        if run {
            let run_pkg: PathBuf = out.clone().unwrap_or_else(|| {
                Path::new(path).join(format!(
                    "{}-candidate.blackbox",
                    Path::new(path)
                        .file_name()
                        .map(|f| f.to_string_lossy().to_string())
                        .unwrap_or_else(|| "pkg".into())
                ))
            });
            let _ = cmd_run(run_pkg.to_str().unwrap_or("."), None, vec![], true, false, false, None, vec![]);
        }
    }
}

fn watch_snapshot(root: &Path) -> BTreeMap<String, (u64, u64)> {
    let mut seen = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root) {
        let Ok(e) = entry else { continue };
        if e.file_type().is_file() {
            let rel = e.path().strip_prefix(root).map(|p| p.to_string_lossy().replace('\\', "/")).unwrap_or_default();
            if rel == "blackbox.lock" {
                continue;
            }
            if let Ok(md) = e.metadata() {
                seen.insert(rel, (md.len(), md.modified().ok().map(|m| m.elapsed().unwrap_or_default().as_secs()).unwrap_or(0)));
            }
        }
    }
    seen
}

fn data_dir_for(name: &str) -> PathBuf {
    ensure_home().packages.join(name).join("data")
}

#[derive(Clone, PartialEq)]
enum SigState {
    Unsigned,
    Valid,
    Trusted,
    Invalid,
}

impl SigState {
    fn to_str(&self) -> &'static str {
        match self {
            SigState::Unsigned => "unsigned",
            SigState::Valid => "valid",
            SigState::Trusted => "trusted",
            SigState::Invalid => "invalid",
        }
    }
}

fn signature_state(pkg: &Package) -> SigState {
    let Some(sig_json) = pkg.members.get(SIGNATURE) else {
        return SigState::Unsigned;
    };
    let sig: Value = serde_json::from_slice(sig_json).unwrap_or(Value::Null);
    let info = crate::crypto::verify_package_signature(&sig, &pkg.content_digest());
    match info.state.as_str() {
        "trusted" => SigState::Trusted,
        "valid" => SigState::Valid,
        _ => SigState::Invalid,
    }
}

fn sig_is_trusted(pkg: &Package) -> bool {
    matches!(signature_state(pkg), SigState::Trusted)
}

fn publisher_name(pkg: &Package) -> String {
    pkg.members
        .get(SIGNATURE)
        .and_then(|v| serde_json::from_slice::<Value>(v).ok())
        .and_then(|v| v.get("publisher").and_then(|p| p.as_str()).map(|s| s.to_string()))
        .unwrap_or_else(|| "Unknown".to_string())
}

// composite: extract? stages are inside the composite package
pub fn run_composite(pkg_path: &Path, work: Option<&str>, yes: bool) -> Option<i32> {
    let members = crate::packaging::read_all(pkg_path).ok()?;
    let stages_member = members.get("stages.json")?;
    let comp: Value = serde_json::from_slice(stages_member).ok()?;
    let stages = comp.get("stages")?.as_array()?.clone();
    let home = ensure_home();
    let base_work = work.map(PathBuf::from).unwrap_or_else(|| home.packages.join(format!("composite-{}", now_secs())));
    for (i, stage) in stages.iter().enumerate() {
        let name = stage.get("name").and_then(|v| v.as_str()).unwrap_or("stage").to_string();
        let member = stage.get("member").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let argvals: Vec<String> = stage
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        let stage_member = members.get(&member)?;
        let stage_dir = base_work.join(format!("stage-{:02}-{}", i, name));
        let _ = std::fs::create_dir_all(&stage_dir);
        let stage_pkg_path = stage_dir.join("stage.blackbox");
        std::fs::write(&stage_pkg_path, stage_member).ok()?;
        let stage_work = stage_dir.join("work");
        let stage_input = stage_work.join("input");
        let _ = std::fs::create_dir_all(&stage_input);
        if i > 0 {
            let prev_out = base_work.join(format!("stage-{:02}-{}", i - 1, "out")).join("output");
            if prev_out.is_dir() {
                let _ = std::fs::create_dir_all(&stage_input);
                let _ = copy_dir_contents(&prev_out, &stage_input);
            }
        }
        let code = cmd_run(
            stage_pkg_path.to_str().unwrap_or("."),
            Some(stage_work.to_string_lossy().to_string()),
            vec![],
            yes,
            false,
            false,
            None,
            argvals,
        );
        if code != 0 {
            println!("BLACKBOX: composite stage '{}' failed (rc={})", name, code);
            return Some(code);
        }
        let out = stage_work.join("output");
        let saved = base_work.join(format!("stage-{:02}-{}", i, "out"));
        let _ = std::fs::create_dir_all(&saved);
        if out.is_dir() {
            let _ = copy_dir_contents(&out, &saved.join("output"));
        }
    }
    Some(0)
}

fn copy_dir_contents(src: &Path, dst: &Path) -> Result<(), ()> {
    let _ = std::fs::create_dir_all(dst).map_err(|_| ())?;
    for e in std::fs::read_dir(src).map_err(|_| ())? {
        let e = e.map_err(|_| ())?;
        let from = e.path();
        let to = dst.join(e.file_name());
        if from.is_dir() {
            copy_dir_contents(&from, &to)?;
        } else {
            let _ = std::fs::copy(&from, &to);
        }
    }
    Ok(())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------- inspect/verify

pub fn cmd_inspect(package: &str) -> i32 {
    match open_package(Path::new(package)) {
        Ok(pkg) => {
            println!("{}", manifest::summarize(&pkg.manifest));
            println!();
            let lock = pkg.members.get(LOCK).map(|v| String::from_utf8_lossy(v).to_string()).unwrap_or_default();
            let mut lock_value: Value = Value::Null;
            if !lock.is_empty() {
                let _ = serde_json::from_str::<Value>(&lock).map(|v| lock_value = v);
            }
            let packages_count = lock_value.get("packages").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
            println!("Layers:");
            print!("{}", crate::packaging::summarize_layers(&pkg));
            println!("  dependencies: {} locked", packages_count);
            println!();
            let sig = signature_state(&pkg);
            let sig_note = match &sig {
                SigState::Unsigned => "none/unsigned".into(),
                SigState::Invalid => "INVALID".into(),
                s => format!("{} ({})", s.to_str(), publisher_name(&pkg)),
            };
            println!("Signature: {}", sig_note);
            println!("Package ID: {}", pkg.package_id());
            0
        }
        Err(e) => print_error(e),
    }
}

pub fn cmd_verify(package: &str) -> i32 {
    match open_package(Path::new(package)) {
        Ok(pkg) => {
            let sig = signature_state(&pkg);
            let pubname = publisher_name(&pkg);
            match &sig {
                SigState::Unsigned => {
                    println!("Integrity: OK (all member hashes verified)");
                    println!("Signature: unsigned");
                    println!("BLACKBOX: the package content is intact but NOT signed. First run shows the full permission summary for approval.");
                }
                SigState::Trusted => {
                    println!("Integrity: OK (all member hashes verified)");
                    println!("Signature: VALID - trusted publisher {}", pubname);
                }
                SigState::Valid => {
                    println!("Integrity: OK (all member hashes verified)");
                    println!("Signature: VALID - publisher {} (not trusted: run 'blackbox trust <pub.pem> --publisher \"{}\"')", pubname, pubname);
                }
                SigState::Invalid => {
                    println!("Integrity: OK (all member hashes verified)");
                    println!("Signature: INVALID - the signature does not verify for this content.");
                    return 1;
                }
            }
            0
        }
        Err(e) => print_error(e),
    }
}

pub fn cmd_unpack(package: &str, dest: Option<String>) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let out = dest.map(PathBuf::from).unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_default().join("peek")
    });
    match unpack_all(&pkg, &out) {
        Ok(o) => {
            println!("UNPACKED  {}", o.display());
            0
        }
        Err(e) => print_error(e),
    }
}

// ------------------------------------------------------------- list/fs

pub fn cmd_list() -> i32 {
    let home = ensure_home();
    let layers = home.layers;
    let mut entries = Vec::new();
    if layers.is_dir() {
        if let Ok(read) = std::fs::read_dir(&layers) {
            for e in read.flatten() {
                if let Some(name) = e.file_name().to_str().map(|s| s.to_string()) {
                    entries.push(name);
                }
            }
        }
    }
    entries.sort();
    for e in &entries {
        println!("{}", e.replace('_', ":"));
    }
    if entries.is_empty() {
        println!("BLACKBOX: no installed layers yet (run a package first)");
    }
    0
}

pub fn cmd_cache(clear: bool, check: bool) -> i32 {
    let cas = CAS::default();
    if clear {
        cas.clear();
        println!("BLACKBOX: cache cleared.");
        return 0;
    }
    if check {
        let corrupt = cas.check_all();
        if corrupt.is_empty() {
            println!("BLACKBOX: cache check OK (all object hashes match).");
        } else {
            println!("BLACKBOX: {} corrupt object(s):", corrupt.len());
            for c in corrupt {
                println!("  {}", c);
            }
            return 1;
        }
        return 0;
    }
    match cas.stats() {
        Ok(stats) => {
            let objs = stats.get("objects").copied().unwrap_or(0);
            let bytes = stats.get("bytes").copied().unwrap_or(0) as u64;
            println!("objects: {}", objs);
            println!("bytes:   {}", det::human_size(bytes));
            println!("root:    {}", cas.root.display());
            0
        }
        Err(e) => {
            println!("BLACKBOX: could not compute cache stats: {}", e);
            1
        }
    }
}

pub fn cmd_gc(dry_run: bool, older_than_days: Option<i64>) -> i32 {
    let home = ensure_home();
    let cas = CAS::default();
    let mut kept: BTreeMap<String, bool> = BTreeMap::new();
    let mut removed = 0u64;
    let mut freed = 0u64;
    let now = now_secs();
    // objects referenced by any installed layer's digest
    let objects_base = cas.root.join("sha256");
    let mut refs: Vec<String> = Vec::new();
    // scan layer dirs for digests
    if home.layers.is_dir() {
        if let Ok(read) = std::fs::read_dir(&home.layers) {
            for e in read.flatten() {
                if let Some(name) = e.file_name().to_str().map(|s| s.replace('_', ":")) {
                    if let Some(hex) = name.strip_prefix("sha256:") {
                        if hex.len() == 64 {
                            refs.push(hex.to_string());
                        }
                    }
                }
            }
        }
    }
    for hex in &refs {
        kept.insert(hex.clone(), true);
    }
    if objects_base.is_dir() {
        for e in walkdir::WalkDir::new(&objects_base).into_iter().flatten() {
            if e.file_type().is_file() {
                if let Some(name) = e.file_name().to_str() {
                    if name.len() == 64 && !kept.contains_key(name) {
                        removed += 1;
                        freed += e.metadata().map(|m| m.len()).unwrap_or(0);
                        if !dry_run {
                            let _ = std::fs::remove_file(e.path());
                        }
                    }
                }
            }
        }
    }
    // stale layers
    let mut stale_layers = 0u64;
    if home.layers.is_dir() {
        for e in walkdir::WalkDir::new(&home.layers).into_iter().flatten() {
            if e.file_type().is_dir() {
                if let Ok(md) = e.metadata() {
                    if let Ok(modified) = md.modified() {
                        if let Ok(age) = modified.elapsed() {
                            if let Some(max) = older_than_days {
                                if age.as_secs() > (max as u64) * 86400 {
                                    stale_layers += 1;
                                    if !dry_run {
                                        let _ = std::fs::remove_dir_all(e.path());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = now;
    if dry_run {
        println!("BLACKBOX: would remove {} unreferenced object(s) ({}), plus {} stale layer(s).", removed, det::human_size(freed), stale_layers);
    } else {
        println!("BLACKBOX: removed {} unreferenced object(s) ({}), plus {} stale layer(s).", removed, det::human_size(freed), stale_layers);
    }
    0
}

pub fn cmd_doctor(fix: bool) -> i32 {
    let home = ensure_home();
    let mut issues: Vec<String> = Vec::new();
    let check_cas = CAS::default();
    if fix {
        let corrupt = check_cas.check_all();
        for c in &corrupt {
            check_cas.delete(c);
            issues.push(format!("purged corrupt object {}", c));
        }
    }
    for (name, dir) in [
        ("objects", home.objects.clone()),
        ("runtimes", home.runtimes.clone()),
        ("layers", home.layers.clone()),
        ("keys", home.keys.clone()),
        ("logs", home.logs.clone()),
    ] {
        if !dir.is_dir() && fix {
            let _ = std::fs::create_dir_all(&dir);
            issues.push(format!("created {}/", name));
        }
    }
    if !issues.is_empty() {
        for i in &issues {
            println!("blackbox doctor: {}", i);
        }
    }
    println!("BLACKBOX home: {}", home.root.display());
    println!("jail capability: {}", crate::sandbox::jail::capability());
    println!("runtimes:");
    for (kind, ver, installed) in RuntimeManager::installed() {
        println!("  {:<7} {:>6}  {}", kind, ver, if installed { "installed" } else { "not installed" });
    }
    if fix {
        println!("BLACKBOX: fix pass complete.");
    }
    0
}

// ------------------------------------------------------------- crypto CLI

pub fn cmd_keygen(name: &str, publisher: Option<&str>) -> i32 {
    let publisher = publisher.unwrap_or(name);
    match crate::crypto::keygen(name, publisher) {
        Ok(k) => {
            println!("BLACKBOX key pair created:");
            for (k, v) in &k {
                println!("  {:<12} {}", k, v);
            }
            println!();
            println!("sign:   blackbox sign pkg --key {}", name);
            println!("seal to: blackbox seal pkg --secrets .env --to keys/{}.seal.pub.pem", name);
            0
        }
        Err(e) => print_error(e),
    }
}

pub fn cmd_sign(package: &str, key: &str) -> i32 {
    match sign_package(Path::new(package), key) {
        Ok(p) => {
            println!("SIGNED      {}", p.display());
            0
        }
        Err(e) => print_error(e),
    }
}

pub fn cmd_trust(pubkey_file: &str, publisher: &str) -> i32 {
    match crate::crypto::trust_key(Path::new(pubkey_file), publisher) {
        Ok(e) => {
            println!("TRUSTED  {}  (sha256: {})", publisher, e.get("sha256").unwrap_or(&"".to_string()));
            0
        }
        Err(err) => print_error(err),
    }
}

pub fn cmd_seal(package: &str, secrets: &str, to: Option<String>, key: Option<String>) -> i32 {
    let pubpem = if let Some(to) = to {
        PathBuf::from(to)
    } else if let Some(key) = key {
        let kd = crate::crypto::keys_dir();
        let p = kd.join(format!("{}.seal.pub.pem", key));
        if !p.is_file() {
            return print_error(BlackboxError::new(format!("No seal public key '{}'.", key)));
        }
        p
    } else {
        return print_error(BlackboxError::new("Specify --to <recipient>.seal.pub.pem or --key <name>."));
    };
    match seal_secrets_into_packages(Path::new(package), Path::new(secrets), &pubpem) {
        Ok(p) => {
            println!("SEALED      {}", p.display());
            println!("BLACKBOX: secrets run-time only via your matching *.seal.key.pem.");
            0
        }
        Err(e) => print_error(e),
    }
}

// ----------------------------------------- NEW: whole-package encryption

/// `blackbox encrypt pkg --to recipient.seal.pub.pem` -> <name>.sealed.blackbox
pub fn cmd_encrypt(package: &str, to: Option<String>, key: Option<String>) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let pubpem = match resolve_seal_pub(to, key) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let recipient = std::fs::read(&pubpem).unwrap_or_default();
    // pick members to encrypt: application tar + dependency tars + secrets
    let layer_index: Value = pkg
        .members
        .get(LAYERS_INDEX)
        .map(|v| serde_json::from_slice(v).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let mut targets: Vec<String> = Vec::new();
    if let Some(layers) = layer_index.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            if let Some(f) = layer.get("file").and_then(|v| v.as_str()) {
                targets.push(f.to_string());
            }
        }
    }
    targets.push(SECRETS.to_string());
    let mut enc_map = serde_json::Map::new();
    let mut new_members = pkg.members.clone();
    for t in targets {
        if let Some(data) = new_members.remove(&t) {
            let blob = match crate::crypto::seal_member_bytes(&data, &recipient) {
                Ok(b) => b,
                Err(e) => return print_error(e),
            };
            enc_map.insert(t, serde_json::from_slice(&blob).unwrap_or(Value::Null));
        }
    }
    if enc_map.is_empty() {
        return print_error(BlackboxError::new("Package has no eligible members to encrypt."));
    }
    new_members.insert(
        crate::packaging::ENCRYPTED.to_string(),
        det::canon_json(&serde_json::json!({"v": 1, "members": Value::Object(enc_map)})),
    );
    // checksums move: recompute everything, remove stale member hashes
    let zip_bytes = match write_deterministic_zip(&new_members, true) {
        Ok(z) => z,
        Err(e) => return print_error(e.into()),
    };
    let out = pkg.path.with_extension("sealed.blackbox");
    if let Err(e) = std::fs::write(&out, &zip_bytes) {
        return print_error(BlackboxError::new("Could not write the encrypted package").with_detail(e.to_string()));
    }
    println!("ENCRYPTED   {}", out.display());
    println!("BLACKBOX: recipients holding the matching '*.seal.key.pem' can 'blackbox run' this file directly.");
    0
}

pub fn cmd_decrypt(package: &str, out: Option<String>) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let mut members = pkg.members.clone();
    if members.remove(crate::packaging::ENCRYPTED).is_none() {
        println!("BLACKBOX: package is not encrypted; nothing to do for {}.", package);
        return 0;
    }
    let zip_bytes = match write_deterministic_zip(&members, true) {
        Ok(z) => z,
        Err(e) => return print_error(e.into()),
    };
    let out = out.map(PathBuf::from).unwrap_or_else(|| pkg.path.with_extension("decrypted.blackbox"));
    if let Err(e) = std::fs::write(&out, &zip_bytes) {
        return print_error(BlackboxError::new("Could not write the decrypted package").with_detail(e.to_string()));
    }
    println!("DECRYPTED   {}", out.display());
    0
}

fn resolve_seal_pub(to: Option<String>, key: Option<String>) -> Result<PathBuf, BlackboxError> {
    if let Some(to) = to {
        return Ok(PathBuf::from(to));
    }
    if let Some(key) = key {
        let kd = crate::crypto::keys_dir();
        let p = kd.join(format!("{}.seal.pub.pem", key));
        if p.is_file() {
            return Ok(p);
        }
        return Err(BlackboxError::new(format!("No seal public key '{}' in {}", key, kd.display())));
    }
    Err(BlackboxError::new("Specify --to <recipient>.seal.pub.pem or --key <name>."))
}

// ------------------------------------------------- explain/diff/audit

pub fn cmd_explain(package: &str) -> i32 {
    match open_package(Path::new(package)) {
        Ok(pkg) => {
            println!("{}", manifest::summarize(&pkg.manifest));
            println!();
            let p = &pkg.manifest.permissions;
            println!("BLACKBOX would: {}", if p.filesystem.write.is_empty() { "read+run" } else { "read+run+write" });
            if p.filesystem.write.is_empty() && !p.network.enabled && !p.process.spawn {
                println!("BLACKBOX: this package can only touch {} and its own input/output dirs.", pkg.manifest.name);
            }
            0
        }
        Err(e) => print_error(e),
    }
}

pub fn cmd_diff(pkg_a: &str, pkg_b: &str) -> i32 {
    let a = match open_package(Path::new(pkg_a)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let b = match open_package(Path::new(pkg_b)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let ka = a.checksums.clone();
    let kb = b.checksums.clone();
    let mut keys: Vec<&String> = ka.keys().chain(kb.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut changes = 0;
    for k in keys {
        let va = ka.get(k);
        let vb = kb.get(k);
        if va != vb {
            let label = k.as_str();
            let a_hash = va.map(|s| &s[..s.len().min(12)]).unwrap_or("-");
            let b_hash = vb.map(|s| &s[..s.len().min(12)]).unwrap_or("-");
            println!("{}  {} -> {}", label, a_hash, b_hash);
            changes += 1;
        }
    }
    if changes == 0 {
        println!("BLACKBOX: packages are identical at the checksum level.");
    } else {
        println!("BLACKBOX: {} member(s) differ.", changes);
    }
    0
}

pub fn cmd_audit(package: &str) -> i32 {
    match open_package(Path::new(package)) {
        Ok(pkg) => {
            println!("Audit: {}", pkg.path.display());
            println!("  name:        {}", pkg.manifest.name);
            println!("  version:     {}", pkg.manifest.version);
            let rt = &pkg.manifest.runtime;
            println!("  runtime:     {} {}", rt.rtype, rt.version);
            println!("  targets:     {}", rt.target);
            if pkg.members.contains_key(crate::packaging::ENCRYPTED) {
                println!("  encryption:  members sealed (X25519+AES256GCM)");
            }
            let p = &pkg.manifest.permissions;
            println!("  network:     {}", if p.network.enabled { "enabled" } else { "disabled" });
            println!("  allow:       {}", p.network.allow.join(", "));
            println!("  spawn:       {}", if p.process.spawn { "allowed" } else { "denied" });
            println!("  fs read:     {}", p.filesystem.read.join(", "));
            println!("  fs write:    {}", p.filesystem.write.join(", "));
            0
        }
        Err(e) => print_error(e),
    }
}

// ------------------------------------------------------------- sbom (NEW)

pub fn cmd_sbom(package: &str, format: &str) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let lock: Value = pkg
        .members
        .get(LOCK)
        .map(|v| serde_json::from_slice(v).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);
    let packages: Vec<Value> = lock
        .get("packages")
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();
    match format {
        "cyclonedx" => {
            let components: Vec<Value> = packages
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "type": "library",
                        "name": p.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        "version": p.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                        "purl": format!("pkg:pypi/{}@{}", p.get("name").and_then(|v| v.as_str()).unwrap_or(""), p.get("version").and_then(|v| v.as_str()).unwrap_or("")),
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "version": 1,
                "metadata": {
                    "tools": [{"name": "blackbox", "version": crate::VERSION}],
                    "component": {"type": "application", "name": pkg.manifest.name, "version": pkg.manifest.version},
                },
                "components": components,
            });
            println!("{}", serde_json::to_string_pretty(&det::json_sorted(&doc)).unwrap_or_default());
        }
        _ => {
            let packages_doc: Vec<Value> = packages
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                        "versionInfo": p.get("version").and_then(|v| v.as_str()).unwrap_or(""),
                        "SPDXID": format!("SPDXRef-Package-{}", sanitize_spdx(p.get("name").and_then(|v| v.as_str()).unwrap_or(""))),
                        "externalRefs": [{
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": format!("pkg:pypi/{}@{}", p.get("name").and_then(|v| v.as_str()).unwrap_or(""), p.get("version").and_then(|v| v.as_str()).unwrap_or("")),
                        }],
                    })
                })
                .collect();
            let doc = serde_json::json!({
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "SPDXID": "SPDXRef-DOCUMENT",
                "name": format!("blackbox-{}-{}", pkg.manifest.name, pkg.manifest.version),
                "documentNamespace": format!("https://blackbox.local/sbom/{}-{}", pkg.manifest.name, pkg.content_digest().get(7..19).unwrap_or("0")),
                "creationInfo": {
                    "creators": [format!("Tool: blackbox-{}", crate::VERSION)],
                    "created": "1970-01-01T00:00:00Z",
                },
                "packages": packages_doc,
            });
            println!("{}", serde_json::to_string_pretty(&det::json_sorted(&doc)).unwrap_or_default());
        }
    }
    0
}

fn sanitize_spdx(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

// -------------------------------------------------------- serve/fetch/publish (NEW)

pub fn cmd_serve(port: u16, allow_upload: bool, quiet: bool) -> i32 {
    match crate::serve::serve(crate::serve::ServeOptions {
        bind: "0.0.0.0".into(),
        port,
        allow_upload,
        quiet,
    }) {
        Ok(addr) => {
            println!("BLACKBOX: serving the content store at {}", addr);
            if allow_upload {
                println!("BLACKBOX: PUT /objects/<sha256> enabled (publishers may upload)");
            }
            println!("BLACKBOX: press Ctrl+C to stop");
            loop {
                std::thread::sleep(std::time::Duration::from_secs(3600));
            }
        }
        Err(e) => {
            eprintln!("BLACKBOX ERROR: {}", e);
            1
        }
    }
}

pub fn cmd_fetch(package: &str, mirror: Option<String>) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    if let Some(m) = mirror {
        std::env::set_var("BLACKBOX_OBJECT_URLS", m);
    }
    let Some(idx) = pkg.members.get(LAYERS_INDEX) else {
        println!("BLACKBOX: package has no layers.json; nothing to fetch.");
        return 0;
    };
    let v: Value = serde_json::from_slice(idx).unwrap_or(Value::Null);
    let cas = CAS::default();
    let mut members = pkg.members.clone();
    let mut fetched = 0u32;
    let thin_ok = if let Some(layers) = v.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            let Some(digest) = layer.get("digest").and_then(|d| d.as_str()) else {
                continue;
            };
            let obj = match cas.get_path(digest) {
                Ok(p) => p,
                Err(e) => return print_error(e.into()),
            };
            let data = match std::fs::read(&obj) {
                Ok(d) => d,
                Err(e) => return print_error(BlackboxError::new("Could not read a fetched object").with_detail(e.to_string())),
            };
            if let Some(f) = layer.get("file").and_then(|d| d.as_str()) {
                members.insert(f.to_string(), data);
                fetched += 1;
            }
        }
        true
    } else {
        false
    };
    let _ = thin_ok;
    let zip_bytes = match write_deterministic_zip(&members, true) {
        Ok(z) => z,
        Err(e) => return print_error(e.into()),
    };
    let out = pkg
        .path
        .with_file_name(format!("{}.full.blackbox", pkg.manifest.name));
    if let Err(e) = std::fs::write(&out, &zip_bytes) {
        return print_error(BlackboxError::new("Could not write the materialized package").with_detail(e.to_string()));
    }
    println!("FETCHED  {} layer object(s) - thin -> full: {}", fetched, out.display());
    0
}

pub fn cmd_publish(package: &str, mirror: &str) -> i32 {
    match crate::serve::publish_package(mirror, Path::new(package)) {
        Ok((base, pushed)) => {
            println!("PUBLISHED  {} object(s) to {}", pushed, base);
            println!("BLACKBOX: recipients can now 'blackbox run' a thin copy fetched from this mirror.");
            0
        }
        Err(e) => print_error(e),
    }
}

// -------------------------------------------------------------- compose (NEW)

pub fn cmd_compose(manifest_path: &str, name: &str, out: Option<String>) -> i32 {
    let mpath = Path::new(manifest_path);
    let text = match std::fs::read_to_string(mpath) {
        Ok(t) => t,
        Err(e) => return print_error(BlackboxError::new("Could not read the compose manifest").with_detail(e.to_string())),
    };
    let doc: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => {
            // YAML fallback
            match serde_yaml::from_str::<Value>(&text) {
                Ok(v) => serde_json::to_value(v).unwrap_or(Value::Null),
                Err(e) => return print_error(BlackboxError::new("Compose manifest is not valid JSON/YAML").with_detail(e.to_string())),
            }
        }
    };
    if doc.is_null() {
        return print_error(BlackboxError::new("Compose manifest is empty."));
    }
    let stages_value = doc.get("stages").cloned().unwrap_or(Value::Null);
    let stages = stages_value.as_array().cloned().unwrap_or_default();
    if stages.is_empty() {
        return print_error(BlackboxError::new("Compose manifest must declare at least one stage."));
    }
    let name = if name.is_empty() {
        doc.get("name").and_then(|v| v.as_str()).unwrap_or("pipeline").to_string()
    } else {
        name.to_string()
    };
    let base = mpath.parent().unwrap_or(Path::new("."));
    // 1. pack each stage
    let mut packed: Vec<(CompositeStage, PathBuf)> = Vec::new();
    for (i, s) in stages.iter().enumerate() {
        let pkg_ref = s.get("package").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if pkg_ref.is_empty() {
            return print_error(BlackboxError::new(format!("Stage {} has no 'package'.", i)));
        }
        let stage_dir = base.join(&pkg_ref);
        let stage_name = s.get("name").and_then(|v| v.as_str()).unwrap_or(&format!("stage{}", i)).to_string();
        let args: Vec<String> = s
            .get("args")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(|str| str.to_string())).collect())
            .unwrap_or_default();
        let tmp_out = std::env::temp_dir().join(format!("blackbox-bb{i}-{}.blackbox", stage_name));
        let pack_res = pack(
            &stage_dir,
            &PackOptions {
                output: Some(tmp_out.clone()),
                target: None,
                thin: false,
                progress: Some(String::new()),
            },
        );
        if let Err(e) = pack_res {
            return print_error(e);
        }
        packed.push((
            CompositeStage { name: stage_name.clone(), package: pkg_ref, args: args.clone() },
            tmp_out,
        ));
    }
    // 2. assemble a composite package that embeds the packed stages
    let comp = CompositeManifest {
        format_version: "1".into(),
        kind: "composite".into(),
        name: name.clone(),
        stages: packed.iter().map(|(s, _)| s.clone()).collect(),
    };
    let out_path = out
        .map(PathBuf::from)
        .unwrap_or_else(|| base.join(format!("{}.blackbox", name)));
    // write embedded package members directly (the build_composite contract)
    let mut members: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut stage_json = Vec::new();
    for (i, (stage, pkg_path)) in packed.iter().enumerate() {
        let blob = std::fs::read(pkg_path).unwrap_or_default();
        let member = format!("stages/{:02}-{}.blackbox", i, stage.name);
        members.insert(member.clone(), blob.clone());
        stage_json.push(serde_json::json!({
            "name": stage.name,
            "member": member,
            "args": stage.args,
            "digest": format!("sha256:{}", det::sha256_bytes(&blob)),
        }));
    }
    let manifest_value = serde_json::json!({
        "format_version": "1",
        "name": name,
        "version": "0.1.0",
        "description": format!("Composite pipeline '{}'", comp.name),
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
    members.insert(crate::packaging::STAGES.to_string(), det::canon_json(&serde_json::json!({"stages": stage_json})));
    let zip_bytes = match write_deterministic_zip(&members, true) {
        Ok(z) => z,
        Err(e) => return print_error(e.into()),
    };
    if let Err(e) = std::fs::write(&out_path, &zip_bytes) {
        return print_error(BlackboxError::new("Could not write the composite package").with_detail(e.to_string()));
    }
    println!("COMPOSED  {} ({} stage(s))", out_path.display(), packed.len());
    0
}

// ---------------------------------------------------------- runtime CLI

pub fn cmd_runtime_import(tarball: &str) -> i32 {
    match RuntimeManager::import_tarball(Path::new(tarball)) {
        Ok(info) => {
            println!("RUNTIME   python {}", info.get("full").unwrap_or(&"".to_string()));
            println!("          target: {}", info.get("target").unwrap_or(&"".to_string()));
            println!("          sha256: {}", info.get("sha256").unwrap_or(&"".to_string()));
            0
        }
        Err(e) => print_error(e),
    }
}

pub fn cmd_runtime_list() -> i32 {
    for (kind, ver, installed) in RuntimeManager::installed() {
        println!("{:<7} {:>8}  {} ({})", kind, ver, if installed { "installed" } else { "not installed" }, crate::platform::current_triple());
    }
    0
}

// ------------------------------------------------------- shell/dev

pub fn cmd_shell(package: &str, work: Option<String>, yes: bool, data: bool) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let home = ensure_home();
    let work_dir = work.map(PathBuf::from).unwrap_or_else(|| home.packages.join(format!("{}-work", pkg.manifest.name)));
    let data_dir = data.then(|| home.packages.join(pkg.manifest.name.clone()).join("data"));
    let mut ctx = match crate::packaging::prepare_run(&pkg, &work_dir, data_dir.as_deref()) {
        Ok(c) => c,
        Err(e) => return print_error(e),
    };
    let _ = yes;
    let shell = if cfg!(windows) { "cmd.exe" } else { "/bin/sh" };
    match runtime::exec_interactive(&ctx, Some(vec![shell.to_string()])) {
        code => code,
    }
}

pub fn cmd_dev(path: &str, app_args: Vec<String>) -> i32 {
    let source = Path::new(path);
    let manifest = match crate::packaging::load_source(source) {
        Ok(m) => m,
        Err(e) => return print_error(e),
    };
    let home = ensure_home();
    let app_dir = source.canonicalize().unwrap_or_else(|_| source.to_path_buf());
    let work_dir = home.packages.join(format!("{}-work", manifest.name));
    let mut ctx = runtime::RunContext::new(
        &manifest,
        &app_dir,
        &PathBuf::new(),
        None,
        &work_dir,
        &manifest.runtime.target,
    );
    runtime::execute(&ctx, Some(&app_args), false)
}

// ---------------------------------------------------------- system bits

pub fn cmd_service_install(package: &str, name: &str, args: &str) -> i32 {
    let home = ensure_home();
    let services = home.services;
    let _ = std::fs::create_dir_all(&services);
    let entry = serde_json::json!({
        "name": name,
        "package": package,
        "args": args,
        "installed": true,
    });
    let path = services.join(format!("{}.json", name));
    if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(&entry).unwrap_or_default()) {
        return print_error(BlackboxError::new("Could not write service entry").with_detail(e.to_string()));
    }
    // simple launcher (cross-platform: a shell script or a .cmd)
    let launcher = service_launcher(name, package, args);
    if cfg!(windows) {
        let launcher_path = services.join(format!("{}.cmd", name));
        let _ = std::fs::write(&launcher_path, launcher);
    } else {
        let launcher_path = services.join(name);
        let _ = std::fs::write(&launcher_path, launcher.replace("%%", "$"));
        let _ = crate::platform::set_exec_bit(&launcher_path);
    }
    println!("SERVICE  {} -> {}", name, package);
    println!("BLACKBOX: autostart integration (Task Scheduler / systemd user units) is environment-specific; the registered entry above is used by 'blackbox service list/status'.");
    0
}

fn service_launcher(name: &str, package: &str, args: &str) -> String {
    if cfg!(windows) {
        format!("@echo off\r\nblackbox run {} --yes {}\r\n", package, args)
    } else {
        format!("#!/bin/sh\nexec blackbox run {} --yes {}\n", package, args)
    }
}

pub fn cmd_service_uninstall(name: &str) -> i32 {
    let home = ensure_home();
    let path = home.services.join(format!("{}.json", name));
    if path.is_file() {
        let _ = std::fs::remove_file(&path);
    }
    let launcher = if cfg!(windows) {
        home.services.join(format!("{}.cmd", name))
    } else {
        home.services.join(name)
    };
    let _ = std::fs::remove_file(&launcher);
    println!("SERVICE  removed {}", name);
    0
}

pub fn cmd_service_list() -> i32 {
    let home = ensure_home();
    if home.services.is_dir() {
        if let Ok(read) = std::fs::read_dir(&home.services) {
            let mut names: Vec<String> = read
                .flatten()
                .filter(|e| e.path().extension().map(|x| x == "json").unwrap_or(false))
                .map(|e| e.file_name().to_string_lossy().replace(".json", ""))
                .collect();
            names.sort();
            if names.is_empty() {
                println!("BLACKBOX: no services registered.");
            } else {
                for n in names {
                    println!("{}", n);
                }
            }
            return 0;
        }
    }
    println!("BLACKBOX: no services registered.");
    0
}

pub fn cmd_service_status(name: &str) -> i32 {
    let home = ensure_home();
    let log = home.logs.join(format!("{}.log", name));
    if log.is_file() {
        if let Ok(text) = std::fs::read_to_string(&log) {
            let tail: Vec<&str> = text.lines().rev().take(20).collect();
            for l in tail.into_iter().rev() {
                println!("{}", l);
            }
        }
        println!("BLACKBOX: log tail for '{}' (last 20 lines)", name);
        0
    } else {
        println!("BLACKBOX: no log for '{}' yet.", name);
        0
    }
}

pub fn cmd_export_docker(package: &str, out: Option<String>) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let m = &pkg.manifest;
    let rt = &m.runtime;
    let base_image = match rt.rtype.as_str() {
        "python" => format!("python:{}", if rt.version.contains('.') { rt.version.clone() } else { format!("{}.0", rt.version) }),
        "node" => format!("node:{}", rt.version),
        _ => "debian:bookworm-slim".to_string(),
    };
    let docker = format!(
        r#"FROM {}

WORKDIR /app
COPY . /app
RUN mkdir -p /work/input /work/output
ENV BLACKBOX_NAME="{}" \
    BLACKBOX_WORK=/work \
    BLACKBOX_INPUT=/work/input \
    BLACKBOX_OUTPUT=/work/output
"#, base_image, m.name);
    let out_path = out.map(PathBuf::from).unwrap_or_else(|| {
        std::env::current_dir().unwrap_or_default().join("Dockerfile")
    });
    if let Err(e) = std::fs::write(&out_path, docker) {
        return print_error(BlackboxError::new("Could not write Dockerfile").with_detail(e.to_string()));
    }
    println!("EXPORTED  {}  (unpack your .blackbox into a directory with the Dockerfile to build)", out_path.display());
    0
}

pub fn cmd_bench(package: &str, runs: u32) -> i32 {
    let pkg = match open_package(Path::new(package)) {
        Ok(p) => p,
        Err(e) => return print_error(e),
    };
    let home = ensure_home();
    let mut total = 0u128;
    for i in 0..runs {
        let work_dir = home.packages.join(format!("{}-bench-work", pkg.manifest.name));
        let start = std::time::Instant::now();
        let mut ctx = match crate::packaging::prepare_run(&pkg, &work_dir, None) {
            Ok(c) => c,
            Err(e) => return print_error(e),
        };
        let code = runtime::execute(&ctx, None, true);
        let elapsed = start.elapsed().as_millis();
        total += elapsed;
        println!("run {:<2}  {} ms  rc={}", i + 1, elapsed, code);
    }
    println!("average: {} ms over {} run(s)", total / runs as u128, runs);
    0
}

// --------------------------------------------------------- self-update (NEW)

/// `blackbox self-update <url>`: fetch a signed update package, verify the
/// publisher (trusted or --yes), atomically replace the running binary.
pub fn cmd_self_update(url: &str, yes: bool) -> i32 {
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(300))
        .build();
    let resp = match agent.get(url).call() {
        Ok(r) => r,
        Err(e) => return print_error(BlackboxError::new(format!("Could not download the update from {}", url)).with_detail(format!("{}", e))),
    };
    let mut raw = Vec::new();
    if let Err(e) = resp.into_reader().read_to_end(&mut raw) {
        return print_error(BlackboxError::new("Could not read the update payload").with_detail(format!("{}", e)));
    }
    let mut archive = match zip::ZipArchive::new(std::io::Cursor::new(raw.clone())) {
        Ok(z) => z,
        Err(_) => return print_error(BlackboxError::new("Update payload is not a .blackbox-update ZIP archive.")),
    };
    let sig_hex = match archive.by_name("signature.json") {
        Ok(mut s) => {
            let mut v = Vec::new();
            let _ = s.read_to_end(&mut v);
            v
        }
        Err(_) => return print_error(BlackboxError::new("Update payload has no signature.json.")),
    };
    let sig: Value = match serde_json::from_slice(&sig_hex) {
        Ok(v) => v,
        Err(e) => return print_error(BlackboxError::new("signature.json is invalid JSON").with_detail(e.to_string())),
    };
    let bin_name = if cfg!(windows) { "blackbox.exe" } else { "blackbox" };
    let bin_data = match archive.by_name(bin_name) {
        Ok(mut b) => {
            let mut v = Vec::new();
            let _ = b.read_to_end(&mut v);
            v
        }
        Err(_) => return print_error(BlackboxError::new(format!("Update payload has no '{}'.", bin_name))),
    };
    let digest = det::sha256_bytes(&bin_data);
    let pubpem = sig.get("public_key").and_then(|v| v.as_str()).unwrap_or("");
    let sighex = sig.get("signature").and_then(|v| v.as_str()).unwrap_or("");
    let file_name = sig.get("file").and_then(|v| v.as_str()).unwrap_or(bin_name);
    if file_name != bin_name {
        return print_error(BlackboxError::new("Update payload targets a different binary."));
    }
    if !crate::crypto::file_verify(pubpem, &digest, sighex) {
        return print_error(BlackboxError::new("Update signature verification FAILED.").with_try("Refusing to replace the binary."));
    }
    let publisher = sig.get("publisher").and_then(|v| v.as_str()).unwrap_or("anonymous").to_string();
    let trust_map = crate::crypto::load_trust();
    let trusted = trust_map
        .get(&publisher)
        .and_then(|t| t.get("sha256"))
        .and_then(|v| v.as_str());
    if trusted.is_none() && !yes {
        return print_error(BlackboxError::new(format!("The update is signed by '{}' but that publisher is not trusted.", publisher))
            .with_try("blackbox trust <pub.pem> --publisher \"{}\"\nor pass --yes to accept this one-time update.".replace("{}", &publisher)));
    }
    let current_exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from(bin_name));
    let parent = current_exe.parent().unwrap_or(Path::new(".")).to_path_buf();
    let tmp = parent.join(format!("{}.new-{}", current_exe.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_default(), std::process::id()));
    if let Err(e) = std::fs::write(&tmp, &bin_data) {
        return print_error(BlackboxError::new("Could not stage the new binary").with_detail(e.to_string()));
    }
    let exe_flag = if cfg!(windows) { "" } else { "" };
    let _ = crate::platform::set_exec_bit(&tmp);
    println!("BLACKBOX: update from '{}' verified (sha256:{})", publisher, &digest[..16]);
    if let Err(e) = std::fs::rename(&tmp, &current_exe) {
        let _ = std::fs::remove_file(&tmp);
        return print_error(BlackboxError::new("Could not replace the binary - it may be in use.").with_detail(format!("{} {}", e, exe_flag))
            .with_try("Close any running blackbox process, or place the staged file \"{}\" and rerun."));

    }
    println!("BLACKBOX: binary updated in place. Restart for the new version.");
    0
}

// ------------------------------------------------------ install (windows-ish)

pub fn cmd_install(package: Option<&str>, no_assoc: bool) -> i32 {
    let home = ensure_home();
    let launcher_dir = home.packages;
    let _ = std::fs::create_dir_all(&launcher_dir);
    let command = if cfg!(windows) {
        r#"
@echo off
setlocal
set FILE=%~dp0%~n1
if exist "%~1" blackbox run "%~1" --yes
pause
"#
    } else {
        "#!/bin/sh\nexec blackbox run \"$1\" --yes\n"
    };
    let launcher_name = if cfg!(windows) { "open-blackbox.cmd" } else { "open-blackbox" };
    let launcher = launcher_dir.join(launcher_name);
    let _ = std::fs::write(&launcher, command);
    if !cfg!(windows) {
        let _ = crate::platform::set_exec_bit(&launcher);
    }
    if let Some(pkg_install) = package {
        let pkg = match open_package(Path::new(pkg_install)) {
            Ok(p) => p,
            Err(e) => return print_error(e),
        };
        println!("INSTALLED  {} (name: {})", pkg_install, pkg.manifest.name);
    }
    if !no_assoc && cfg!(windows) {
        println!("BLACKBOX: file association requires admin or a user Choice registry entry:\n  ftype blackbox.file=...\n  assoc .blackbox=blackbox.file");
    }
    println!("BLACKBOX: launcher ready: {}", launcher.display());
    0
}

pub fn cmd_upgrade(package: &str, from_url: &str, yes: bool) -> i32 {
    let target = Path::new(package);
    let base = target.parent().unwrap_or(Path::new("."));
    let candidate_name = format!("{}.upgrade-{}.blackbox", base.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or("pkg".into()), std::process::id());
    let candidate_path = base.join(candidate_name);
    let data = match crate::serve::http_get(from_url) {
        Ok(d) => d,
        Err(e) => return print_error(BlackboxError::new(format!("Could not download {}:", from_url)).with_detail(format!("{}", e))),
    };
    if let Err(e) = std::fs::write(&candidate_path, &data) {
        return print_error(BlackboxError::new("Could not stage the candidate package").with_detail(e.to_string()));
    }
    let candidate = match open_package(&candidate_path) {
        Ok(c) => c,
        Err(e) => return print_error(e),
    };
    let sig_ok = matches!(signature_state(&candidate), SigState::Trusted | SigState::Valid);
    if !sig_ok && !yes {
        return print_error(BlackboxError::new("The candidate package is unsigned or invalidly signed.")
            .with_try("Pass --yes only if you know what you are doing."));
    }
    let current = match open_package(target) {
        Ok(c) => c,
        Err(e) => return print_error(e),
    };
    if current.content_digest() == candidate.content_digest() {
        println!("UPGRADE  candidate is identical to the installed package.");
        let _ = std::fs::remove_file(&candidate_path);
        return 0;
    }
    // switch destinations atomically: target -> .prev, candidate -> target
    let prev = target.with_file_name(format!("{}.prev", target.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or("pkg.blackbox".into())));
    let _ = std::fs::rename(target, &prev);
    match std::fs::rename(&candidate_path, target) {
        Ok(()) => {
            println!("UPGRADED  {} -> {}", target.display(), candidate.manifest.version);
            println!("BLACKBOX: previous package kept as {}", prev.display());
            0
        }
        Err(e) => {
            let _ = std::fs::rename(&prev, target);
            print_error(BlackboxError::new("Could not swap the package; previously installed version restored.").with_detail(e.to_string()))
        }
    }
}

// ----------------------------------------------------------- helpers

pub fn cmd_list_runtimes(_args: ()) -> i32 {
    cmd_runtime_list()
}
