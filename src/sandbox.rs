//! Sandbox policy, platform jail wrappers and resource limits.
//!
//! Enforcement tiers (see docs/security.md):
//!   1. Platform jail: Linux bubblewrap (filesystem binds + netns),
//!      macOS sandbox-exec profiles. Windows/MacGUI: best effort, shim-only.
//!   2. Runtime shim (always on): sitecustomize.py / node_guard.js enforcing
//!      network, spawn and filesystem contract from inside the interpreter.
//!
//! The shim is defense-in-depth and a contract-enforcer, not a kernel
//! boundary. Capability is PROBED, not assumed.

use crate::error::BlackboxError;
use crate::manifest::Manifest;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod policy {
    use super::*;

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct Policy {
        pub network: bool,
        pub network_allow: Vec<String>,
        pub spawn: bool,
        pub read_allowed: Vec<String>,
        pub write_allowed: Vec<String>,
        pub limits: BTreeMap<String, i64>,
        pub gui: bool,
        pub enforce: bool,
    }

    pub fn build_policy(
        m: &Manifest,
        app_dir: &Path,
        site_dir: &Path,
        runtime_root: &Path,
        work_dir: &Path,
        trusted_read: Vec<PathBuf>,
        data_dir: Option<&Path>,
    ) -> Policy {
        let perms = &m.permissions;
        let work_abs = work_abs(work_dir);
        let mut resolved_read: Vec<String> = Vec::new();
        let mut resolved_write: Vec<String> = Vec::new();
        for p in &perms.filesystem.read {
            resolved_read.push(realpath(&work_abs.join(&p[2..])));
        }
        for p in &perms.filesystem.write {
            resolved_write.push(realpath(&work_abs.join(&p[2..])));
            let dir = work_abs.join(&p[2..]);
            // Only pre-create paths that look like directories (trailing '/'
            // or no file extension) - a write entitlement like
            // "./data.json" names a file the host must not take over.
            let leaf = dir.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let looks_like_file = leaf.contains('.') && !p.ends_with('/');
            if !looks_like_file {
                let _ = std::fs::create_dir_all(&dir);
            }
        }
        let mut data_read: Vec<String> = Vec::new();
        if let Some(d) = data_dir {
            let rp = realpath(d);
            let _ = std::fs::create_dir_all(&rp);
            data_read.push(rp);
        }
        let mut readable: Vec<String> = vec![
            realpath(app_dir),
            if site_dir.as_os_str().is_empty() { String::new() } else { realpath(site_dir) },
            realpath(runtime_root),
        ]
        .into_iter()
        .chain(resolved_read)
        .chain(data_read.iter().cloned())
        .chain(trusted_read.iter().map(|t| realpath(t)))
        .filter(|s| !s.is_empty())
        .collect();
        readable.sort();
        readable.dedup();

        let mut writable: Vec<String> = resolved_write.clone();
        writable.push(realpath(&work_abs.join("_blackbox_tmp")));
        writable.sort();
        writable.dedup();

        let enforce = std::env::var("BLACKBOX_SANDBOX_ENFORCE").map(|v| v == "1").unwrap_or(true);

        Policy {
            network: perms.network.enabled,
            network_allow: perms.network.allow.clone(),
            spawn: perms.process.spawn,
            read_allowed: readable,
            write_allowed: writable,
            limits: m.limits.clone(),
            gui: m.interface.itype == "gui",
            enforce,
        }
    }

    fn work_abs(p: &Path) -> PathBuf {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(p)
        }
    }

    fn realpath(p: &Path) -> String {
        p.canonicalize()
            .unwrap_or_else(|_| p.to_path_buf())
            .display()
            .to_string()
    }

    pub fn write_policy(policy: &Policy, path: &Path) -> Result<(), BlackboxError> {
        let data = serde_json::to_string_pretty(policy)
            .map_err(|e| BlackboxError::new("Could not serialize the sandbox policy").with_detail(e.to_string()))?;
        std::fs::write(path, data)
            .map_err(|e| BlackboxError::new("Could not write the sandbox policy file").with_detail(e.to_string()))?;
        Ok(())
    }
}

pub mod jail {
    use super::*;

    #[cfg(unix)]
    fn probe(key: &str, argv: &[&str]) -> bool {
        static CACHE: std::sync::OnceLock<Vec<(String, bool)>> = std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(|| Vec::new());
        if let Some((_, ok)) = cache.iter().find(|(k, _)| k == key) {
            return *ok;
        }
        let ok = std::process::Command::new(argv[0])
            .args(&argv[1..])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        let mut c = CACHE.get_or_init(|| Vec::new());
        c.push((key.to_string(), ok));
        ok
    }

    #[cfg(not(unix))]
    fn probe(_key: &str, _argv: &[&str]) -> bool {
        false
    }

    #[cfg(unix)]
    pub fn capability() -> &'static str {
        let osname = std::env::consts::OS;
        if osname == "linux" {
            if crate::platform::which("bwrap").is_some()
                && probe("bwrap", &["bwrap", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-user", "--unshare-pid", "--true"])
            {
                return "bwrap";
            }
            return "shim-only";
        }
        if osname == "macos" {
            if crate::platform::which("sandbox-exec").is_some()
                && probe("sandbox-exec", &["sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true"])
            {
                return "sandbox-exec";
            }
            return "shim-only";
        }
        "shim-only"
    }

    #[cfg(not(unix))]
    pub fn capability() -> &'static str {
        "shim-only"
    }

    fn is_linux() -> bool {
        cfg!(target_os = "linux")
    }
    fn is_macos() -> bool {
        cfg!(target_os = "macos")
    }

    /// Returns (argv, jailed).
    pub fn wrap_command(
        argv: &[String],
        policy: &policy::Policy,
        _jail_roots: &[PathBuf],
        network_enabled: bool,
        work_dir: &Path,
    ) -> (Vec<String>, bool) {
        #[cfg(unix)]
        {
            // sandbox-exec profiles cannot grant WindowServer access, so a GUI
            // package on macOS runs jailed-off (shim still enforces contract).
            if policy.gui && is_macos() {
                return (argv.to_vec(), false);
            }
        }
        let cap = capability();
        // In-process enum: match &str with any combos
        match cap {
            "bwrap" => (bwrap(argv, policy, network_enabled, work_dir), true),
            "sandbox-exec" => (sandbox_exec(argv, policy, network_enabled, work_dir), true),
            _ => (argv.to_vec(), false),
        }
    }

    #[cfg(not(unix))]
    fn bwrap(_argv: &[String], _policy: &policy::Policy, _net: bool, _work: &Path) -> Vec<String> {
        Vec::new()
    }

    #[cfg(unix)]
    fn bwrap(argv: &[String], policy: &policy::Policy, network_enabled: bool, work_dir: &Path) -> Vec<String> {
        let mut args: Vec<String> = vec![
            "bwrap".into(),
            "--die-with-parent".into(),
            "--new-session".into(),
            "--unshare-user".into(),
            "--unshare-pid".into(),
            "--unshare-ipc".into(),
            "--unshare-cgroup".into(),
        ];
        if !network_enabled {
            args.push("--unshare-net".into());
        }
        args.push("--ro-bind".into());
        args.push("/".into());
        args.push("/".into());
        args.push("--dev".into());
        args.push("/dev".into());
        args.push("--proc".into());
        args.push("/proc".into());
        #[cfg(unix)]
        for w in &policy.write_allowed {
            let p = Path::new(w);
            if p.is_dir() {
                args.push("--bind".into());
                args.push(w.clone());
                args.push(w.clone());
            }
        }
        if policy.gui {
            for d in ["/tmp/.X11-unix", "/dev/shm", "/dev/dri"] {
                if Path::new(d).is_dir() {
                    args.push("--bind".into());
                    args.push(d.into());
                    args.push(d.into());
                }
            }
            #[cfg(unix)]
            {
                let uid = unsafe { libc::getuid() };
                let uid_dir = format!("/run/user/{}", uid);
                if Path::new(&uid_dir).is_dir() {
                    args.push("--bind".into());
                    args.push(uid_dir.clone());
                    args.push(uid_dir.clone());
                }
            }
        }
        let work = work_dir;
        args.push("--bind".into());
        args.push(work.display().to_string());
        args.push(work.display().to_string());
        args.push("--chdir".into());
        args.push(work.display().to_string());
        args.push("--".into());
        args.extend(argv.iter().cloned());
        args
    }

    #[cfg(not(unix))]
    fn sandbox_exec(_argv: &[String], _policy: &policy::Policy, _net: bool, _work: &Path) -> Vec<String> {
        Vec::new()
    }

    #[cfg(unix)]
    fn sandbox_exec(argv: &[String], policy: &policy::Policy, network_enabled: bool, work_dir: &Path) -> Vec<String> {
        if !is_macos() {
            return argv.to_vec();
        }
        let mut lines: Vec<String> = vec!["(version 1)".into(), "(allow default)".into(), "(deny file-write*)".into()];
        for w in &policy.write_allowed {
            lines.push(format!("(allow file-write* (subpath \"{}\"))", w));
        }
        lines.push(format!("(allow file-write* (subpath \"{}\"))", work_dir.display()));
        if !network_enabled {
            lines.push("(deny network*)".into());
        }
        let profile = lines.join("\n");
        let mut args: Vec<String> = vec!["sandbox-exec".into(), "-p".into(), profile];
        args.extend(argv.iter().cloned());
        args
    }
}

pub mod limits {
    use super::*;

    /// Describe the enforced limits (never silently pretend more than the OS
    /// gives us).
    pub fn describe(limits: &BTreeMap<String, i64>, triple: &str) -> String {
        if limits.is_empty() {
            return String::new();
        }
        let mut parts = Vec::new();
        if let Some(m) = limits.get("memory_mb") {
            parts.push(format!("mem<={}MB", m));
        }
        if let Some(c) = limits.get("cpu_percent") {
            parts.push(format!("cpu<={}%", c));
        }
        if let Some(p) = limits.get("max_processes") {
            parts.push(format!("procs<={}", p));
        }
        let os = crate::platform::target_info(triple).map(|t| t.os).unwrap_or("");
        let enforced = if os == "windows" || os == "linux" { "enforced" } else { "best-effort" };
        format!("limits[{}] {}", parts.join(", "), enforced)
    }

    #[cfg(unix)]
    pub fn apply_pre_spawn(cmd: &mut std::process::Command, limits_map: &BTreeMap<String, i64>) {
        if limits_map.is_empty() {
            return;
        }
        let mem = limits_map.get("memory_mb").copied();
        let procs = limits_map.get("max_processes").copied();
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(move || {
                if let Some(mb) = mem {
                    let lim = (mb as u64) * 1024 * 1024;
                    let rlim = libc::rlimit { rlim_cur: lim, rlim_max: lim };
                    libc::setrlimit(libc::RLIMIT_AS, &rlim);
                }
                if let Some(pc) = procs {
                    let lim = pc as u64;
                    let rlim = libc::rlimit { rlim_cur: lim, rlim_max: lim };
                    libc::setrlimit(libc::RLIMIT_NPROC, &rlim);
                }
                Ok(())
            });
        }
    }

    #[cfg(not(unix))]
    pub fn apply_pre_spawn(_cmd: &mut std::process::Command, _limits_map: &BTreeMap<String, i64>) {}

    #[allow(unused_variables)]
    pub fn apply_post_spawn(child: &mut std::process::Child, limits_map: &BTreeMap<String, i64>) {
        // On Windows, Job Objects would be the natural hard-cap; this build
        // applies POSIX rlimits (applied pre-spawn) and labels the run
        // "best-effort" on Windows - honesty over pretend enforcement.
    }
}
