//! BLACKBOX run internals: assemble, isolate, execute.
//!
//! A run composes the provisioned interpreter (hash-verified), the shared
//! content-addressed layers, a scrubbed environment, the manifest
//! permissions materialized as an enforceable policy, and a platform jail
//! where one exists. The host's own Python/Node installation is never used.

use crate::error::BlackboxError;
use crate::manifest::Manifest;
use crate::runtime::providers::get_provider;
use crate::sandbox::{jail, limits};
use crate::storage::ensure_home;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;

pub const SHIM_NAMES: &[&str] = &["sitecustomize.py", "node_guard.js"];
const WEB_URL_RE: &[&str] = &["127.0.0.1:", "localhost:"];

#[derive(Debug, Clone)]
pub struct RunContext {
    pub manifest: Manifest,
    pub app_dir: PathBuf,
    pub site_dir: PathBuf,
    pub runtime_exe: Option<PathBuf>,
    pub work_dir: PathBuf,
    pub triple: String,
    pub data_dir: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub entry: Option<String>,
    pub secrets: Option<BTreeMap<String, String>>,
    pub sealed_error: Option<String>,
}

impl RunContext {
    pub fn new(
        manifest: &Manifest,
        app_dir: &Path,
        site_dir: &Path,
        runtime_exe: Option<&Path>,
        work_dir: &Path,
        triple: &str,
    ) -> Self {
        RunContext {
            manifest: manifest.clone(),
            app_dir: app_dir.to_path_buf(),
            site_dir: site_dir.to_path_buf(),
            runtime_exe: runtime_exe.map(|p| p.to_path_buf()),
            work_dir: work_dir.to_path_buf(),
            triple: triple.to_string(),
            data_dir: None,
            log_file: None,
            entry: None,
            secrets: None,
            sealed_error: None,
        }
    }

    pub fn input_dir(&self) -> PathBuf {
        self.work_dir.join("input")
    }
    pub fn output_dir(&self) -> PathBuf {
        self.work_dir.join("output")
    }
}

pub fn shim_dir() -> PathBuf {
    let home = ensure_home();
    let dest = home.shim;
    let _ = std::fs::create_dir_all(&dest);
    for name in SHIM_NAMES {
        if let Some(payload) = crate::templates::shim_payload(name) {
            let dest_file = dest.join(name);
            let existing = std::fs::read(&dest_file).ok();
            if existing.as_deref() != Some(payload.as_bytes()) {
                let _ = std::fs::write(&dest_file, payload.as_bytes());
            }
        }
    }
    dest
}

#[derive(Debug, Clone)]
pub struct Launch {
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub jailed: bool,
    pub policy: serde_json::Value,
    pub limits: BTreeMap<String, i64>,
    pub enforcement: String,
}

pub fn build_launch(
    ctx: &RunContext,
    extra_args: Option<&[String]>,
    argv_override: Option<Vec<String>>,
) -> Result<Launch, BlackboxError> {
    let m = &ctx.manifest;
    let rt = &m.runtime;
    let provider = get_provider(&rt.rtype)?;
    std::fs::create_dir_all(ctx.input_dir())
        .map_err(|e| BlackboxError::new("Could not create input dir").with_detail(e.to_string()))?;
    std::fs::create_dir_all(ctx.output_dir())
        .map_err(|e| BlackboxError::new("Could not create output dir").with_detail(e.to_string()))?;
    let tmp_dir = ctx.work_dir.join("_blackbox_tmp");
    std::fs::create_dir_all(&tmp_dir)
        .map_err(|e| BlackboxError::new("Could not create tmp dir").with_detail(e.to_string()))?;

    let is_win = crate::platform::target_info(&ctx.triple).map(|t| t.os == "windows").unwrap_or(false);

    let exe_dir = if rt.rtype == "native" || rt.rtype == "rust" {
        ctx.app_dir.clone()
    } else {
        ctx.runtime_exe
            .as_ref()
            .map(|p| p.parent().map(|d| d.to_path_buf()).unwrap_or_default())
            .unwrap_or_default()
    };

    let use_shim = rt.rtype == "python" || rt.rtype == "node";
    let shim = if use_shim { Some(shim_dir()) } else { None };

    let mut policy = crate::sandbox::policy::build_policy(
        m,
        &ctx.app_dir,
        &ctx.site_dir,
        &exe_dir,
        &ctx.work_dir,
        shim.as_ref().map(|s| vec![s.clone()]).unwrap_or_default(),
        ctx.data_dir.as_deref(),
    );
    // store limits inside policy payload too
    policy.limits = m.limits.clone();
    let policy_path = ctx.work_dir.join("_blackbox_policy.json");
    crate::sandbox::policy::write_policy(&policy, &policy_path)?;

    // ---- environment
    let mut env = BTreeMap::new();
    let mut path_dirs: Vec<PathBuf> = vec![exe_dir.clone()];
    if is_win {
        let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        path_dirs.push(PathBuf::from(sysroot).join("System32"));
        env.insert("SYSTEMROOT".into(), std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()));
        for k in ["APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "COMSPEC"] {
            if let Ok(v) = std::env::var(k) {
                env.insert(k.to_string(), v);
            }
        }
    } else {
        path_dirs.push(PathBuf::from("/usr/bin"));
        path_dirs.push(PathBuf::from("/bin"));
        if m.interface.itype == "gui" {
            for k in ["DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_TYPE"] {
                if let Ok(v) = std::env::var(k) {
                    env.insert(k.to_string(), v);
                }
            }
        }
    }
    env.insert("PATH".into(), std::env::join_paths(path_dirs).unwrap_or_default().to_string_lossy().to_string());
    env.insert("TMPDIR".into(), tmp_dir.display().to_string());
    env.insert("TEMP".into(), tmp_dir.display().to_string());
    env.insert("TMP".into(), tmp_dir.display().to_string());
    env.insert("HOME".into(), ctx.work_dir.display().to_string());
    env.insert("USERPROFILE".into(), ctx.work_dir.display().to_string());
    env.insert("BLACKBOX_NAME".into(), m.name.clone());
    env.insert("BLACKBOX_WORK".into(), ctx.work_dir.display().to_string());
    env.insert("BLACKBOX_INPUT".into(), ctx.input_dir().display().to_string());
    env.insert("BLACKBOX_OUTPUT".into(), ctx.output_dir().display().to_string());
    env.insert("BLACKBOX_SANDBOX_POLICY".into(), policy_path.display().to_string());
    if let Some(d) = &ctx.data_dir {
        env.insert("BLACKBOX_DATA".into(), d.display().to_string());
    }

    for (k, v) in provider.env(ctx.runtime_exe.as_deref(), &ctx.site_dir, &ctx.app_dir, &ctx.triple) {
        if env.contains_key(&k) {
            let old = env.remove(&k).unwrap_or_default();
            env.insert(k.clone(), format!("{};{}", old, v));
        } else {
            env.insert(k, v);
        }
    }
    if use_shim {
        let shim_path = shim.as_ref().unwrap();
        if let Some(py) = env.get("PYTHONPATH") {
            env.insert("PYTHONPATH".into(), format!("{}{}{}", shim_path.display(), std::path::MAIN_SEPARATOR, py));
        } else if rt.rtype == "python" {
            env.insert("PYTHONPATH".into(), shim_path.display().to_string());
        }
        if rt.rtype == "node" {
            if let Some(guard) = shim_path.join("node_guard.js").is_file().then(|| shim_path.join("node_guard.js")) {
                let current = env.get("NODE_OPTIONS").cloned().unwrap_or_default();
                let updated = format!("--require {} {}", guard.display(), current).trim().to_string();
                env.insert("NODE_OPTIONS".into(), updated);
            }
        }
    }
    for (k, v) in &m.environment.variables {
        env.insert(k.clone(), v.clone());
    }
    if let Some(secrets) = &ctx.secrets {
        for (k, v) in secrets {
            env.insert(k.clone(), v.clone());
        }
    }

    // ---- argv
    let argv = if let Some(av) = argv_override {
        av
    } else {
        let ep = if let Some(name) = &ctx.entry {
            let Some(sub) = m.entrypoints.get(name) else {
                let avail = m.entrypoints.keys().cloned().collect::<Vec<_>>().join(", ");
                let avail = if avail.is_empty() { "(none defined)".to_string() } else { avail };
                return Err(BlackboxError::new(format!("Package '{}' has no subcommand '{}'.", m.name, name))
                    .with_try(format!("Available subcommands: {}", avail)));
            };
            (sub.command.clone(), sub.args.clone())
        } else {
            (m.entrypoint.command.clone(), m.entrypoint.args.clone())
        };
        let mut merged = ep.1.clone();
        if let Some(extra) = extra_args {
            merged.extend(extra.iter().cloned());
        }
        provider.resolve_command(&ep.0, &merged, ctx.runtime_exe.as_deref(), &ctx.app_dir, m)?
    };

    let (wrapped, jailed) = jail::wrap_command(
        &argv,
        &policy,
        &[exe_dir.clone()]
            .into_iter()
            .chain(vec![ctx.site_dir.clone()])
            .chain(vec![ctx.app_dir.clone()])
            .chain(shim.clone().into_iter().collect::<Vec<_>>())
            .chain(vec![ctx.work_dir.clone()])
            .collect::<Vec<_>>(),
        m.permissions.network.enabled,
        &ctx.work_dir,
    );
    let mut tiers: Vec<&str> = Vec::new();
    if jailed {
        tiers.push("platform jail");
    }
    if use_shim {
        tiers.push("runtime shim");
    }
    let enforcement = if tiers.is_empty() {
        "environment isolation only".to_string()
    } else {
        tiers.join(" + ")
    };

    Ok(Launch {
        argv: wrapped,
        env,
        cwd: ctx.work_dir.clone(),
        jailed,
        policy: serde_json::to_value(&policy).unwrap_or(serde_json::Value::Null),
        limits: m.limits.clone(),
        enforcement,
    })
}

pub fn exec_interactive(ctx: &RunContext, argv_override: Option<Vec<String>>) -> i32 {
    let launch = match build_launch(ctx, None, argv_override) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("BLACKBOX ERROR: {}", e.summary);
            return 1;
        }
    };
    println!("BLACKBOX: interactive [{}] - type 'exit' to leave.", launch.enforcement);
    let mut cmd = std::process::Command::new(&launch.argv[0]);
    cmd.args(&launch.argv[1..]);
    cmd.current_dir(&launch.cwd);
    cmd.env_clear();
    for (k, v) in &launch.env {
        cmd.env(k, v);
    }
    match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("BLACKBOX ERROR: could not start the command: {}", e);
            1
        }
    }
}

fn spawn_child(launch: &Launch) -> Result<std::process::Child, BlackboxError> {
    let mut cmd = std::process::Command::new(&launch.argv[0]);
    cmd.args(&launch.argv[1..]);
    cmd.current_dir(&launch.cwd);
    cmd.env_clear();
    for (k, v) in &launch.env {
        cmd.env(k, v);
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    limits::apply_pre_spawn(&mut cmd, &launch.limits);
    let mut child = cmd.spawn()
        .map_err(|e| BlackboxError::new(format!("Could not start the package process.")).with_detail(format!("{}", e)))?;
    limits::apply_post_spawn(&mut child, &launch.limits);
    Ok(child)
}

pub fn execute(ctx: &RunContext, extra_args: Option<&[String]>, quiet: bool) -> i32 {
    let launch = match build_launch(ctx, extra_args, None) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{}", crate::error::render_error(&e));
            return 1;
        }
    };
    let m = &ctx.manifest;
    if !quiet {
        println!("BLACKBOX: running {} {} [{}]", m.name, m.version, launch.enforcement);
        if let Some(err) = &ctx.sealed_error {
            println!("BLACKBOX: sealed secrets NOT loaded - {}", err);
        } else if ctx.secrets.is_some() {
            println!("BLACKBOX: sealed secrets loaded ({} variable(s))", ctx.secrets.as_ref().map(|s| s.len()).unwrap_or(0));
        }
        let lim = limits::describe(&m.limits, &ctx.triple);
        if !lim.is_empty() {
            println!("BLACKBOX: {}", lim);
        }
        if m.interface.itype == "web" {
            println!("BLACKBOX: waiting for the app's local server...");
        }
        if m.interface.itype == "gui" && crate::platform::target_info(&ctx.triple).map(|t| t.os == "macos").unwrap_or(false) && !launch.jailed {
            println!("BLACKBOX: note - GUI on macOS runs without sandbox-exec (WindowServer access cannot be granted via profile); the runtime shim still enforces the contract.");
        }
    }

    let mut child = match spawn_child(&launch) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", crate::error::render_error(&e));
            return 1;
        }
    };

    let (tx, rx) = mpsc::channel::<String>();
    let tx_out = tx.clone();
    let tx_err = tx.clone();
    drop(tx);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let handle_stdout = std::thread::spawn(move || {
        if let Some(mut stream) = stdout {
            use std::io::BufRead;
            let mut buf = String::new();
            loop {
                buf.clear();
                match std::io::BufReader::new(&mut stream).read_line(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx_out.send(buf.clone()).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    let handle_stderr = std::thread::spawn(move || {
        if let Some(mut stream) = stderr {
            use std::io::BufRead;
            let mut buf = String::new();
            loop {
                buf.clear();
                match std::io::BufReader::new(&mut stream).read_line(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx_err.send(buf.clone()).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    drop(handle_stdout);
    drop(handle_stderr);

    let mut log_writer: Option<std::fs::File> = None;
    if let Some(log_path) = &ctx.log_file {
        if let Some(parent) = log_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(log_path) {
            use std::io::Write;
            let header = format!("\n===== {} {} run @ {} =====\n", m.name, m.version, now_secs());
            let _ = f.write_all(header.as_bytes());
            log_writer = Some(f);
        }
    }

    let mut shown_url = false;
    let mut tail: Vec<String> = Vec::with_capacity(120);
    while let Ok(line) = rx.recv() {
        push_tail(&mut tail, &line);
        print!("{}", line);
        use std::io::Write;
        let _ = std::io::stdout().flush();
        if let Some(f) = log_writer.as_mut() {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
        if m.interface.itype == "web" && !shown_url {
            for needle in WEB_URL_RE {
                if let Some(idx) = line.find(needle) {
                    let rest = &line[idx + needle.len()..];
                    let port: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
                    let port = port.trim_matches(char::is_whitespace);
                    if port.len() >= 2 && !port.is_empty() {
                        let shown = format!("BLACKBOX: {} is live at  http://127.0.0.1:{}", m.name, port.trim());
                        println!("{}", shown);
                        shown_url = true;
                        break;
                    }
                }
            }
        }
    }
    let rc = child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);
    if rc != 0 {
        crash_bundle(ctx, rc, &tail);
    }
    rc
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn push_tail(tail: &mut Vec<String>, line: &str) {
    if tail.len() >= 120 {
        tail.remove(0);
    }
    tail.push(line.trim_end_matches('\n').to_string());
}

fn crash_bundle(ctx: &RunContext, rc: i32, tail: &[String]) {
    let home = ensure_home();
    let d = home.logs;
    let _ = std::fs::create_dir_all(&d);
    let name = ctx.manifest.name.clone();
    let p = d.join(format!("crash-{}-{}.json", name, now_secs()));
    let body = serde_json::json!({
        "package": name,
        "version": ctx.manifest.version,
        "exit_code": rc,
        "triple": ctx.triple,
        "network": {"enabled": ctx.manifest.permissions.network.enabled, "allow": ctx.manifest.permissions.network.allow},
        "limits": ctx.manifest.limits,
        "output_tail": tail,
    });
    if let Ok(text) = serde_json::to_string_pretty(&body) {
        let _ = std::fs::write(&p, text);
        println!("BLACKBOX: wrote crash bundle {}", p.display());
    }
}

/// Execute and capture stdout/stderr for GUI
pub fn execute_capture(ctx: &RunContext, extra_args: Option<&[String]>) -> Result<(String, String, i32), BlackboxError> {
    let launch = build_launch(ctx, extra_args, None)?;

    let mut child = spawn_child(&launch)?;

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let mut stdout_buf = String::new();
    let mut stderr_buf = String::new();

    if let Some(mut stream) = stdout {
        use std::io::Read;
        let _ = stream.read_to_string(&mut stdout_buf);
    }
    if let Some(mut stream) = stderr {
        use std::io::Read;
        let _ = stream.read_to_string(&mut stderr_buf);
    }

    let rc = child.wait().map(|s| s.code().unwrap_or(1)).unwrap_or(1);

    if rc != 0 {
        let mut tail = Vec::new();
        for line in stdout_buf.lines().chain(stderr_buf.lines()).take(120) {
            tail.push(line.to_string());
        }
        crash_bundle(ctx, rc, &tail);
    }

    Ok((stdout_buf, stderr_buf, rc))
}

