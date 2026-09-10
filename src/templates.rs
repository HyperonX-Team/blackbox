//! Embedded project templates (`blackbox init`) and runtime shims.
//!
//! Templates are compiled into the binary: `blackbox init` works offline,
//! no package data and no network needed. Shims are the in-process
//! enforcement layer that every python/node run places into
//! ~/.blackbox/sandbox-shim.

pub const HELLO_BLACKBOX_YAML: &str = include_str!("../blackbox/cli/templates/hello/blackbox.yaml");
pub const HELLO_REQUIREMENTS: &str = include_str!("../blackbox/cli/templates/hello/requirements.txt");
pub const HELLO_MAIN_PY: &str = include_str!("../blackbox/cli/templates/hello/src/main.py");

pub const DATASIFT_BLACKBOX_YAML: &str = include_str!("../blackbox/cli/templates/datasift/blackbox.yaml");
pub const DATASIFT_REQUIREMENTS: &str = include_str!("../blackbox/cli/templates/datasift/requirements.txt");
pub const DATASIFT_MAIN_PY: &str = include_str!("../blackbox/cli/templates/datasift/src/main.py");
pub const DATASIFT_SAMPLE_CSV: &str = include_str!("../blackbox/cli/templates/datasift/src/sample.csv");

pub const NODE_BLACKBOX_YAML: &str = include_str!("../blackbox/cli/templates/node/blackbox.yaml");
pub const NODE_PACKAGE_JSON: &str = include_str!("../blackbox/cli/templates/node/package.json");
pub const NODE_MAIN_JS: &str = include_str!("../blackbox/cli/templates/node/src/index.js");

pub const SHIM_SITECUSTOMIZE: &str = include_str!("../blackbox/sandbox/shim/sitecustomize.py");
pub const SHIM_NETMATCH: &str = include_str!("../blackbox/sandbox/shim/netmatch.py");

/// Node in-process guard (blocks spawn where denied, network where denied).
pub const NODE_GUARD_JS: &str = r#"// BLACKBOX runtime shim: in-process enforcement (defense-in-depth)
'use strict';
try {
  const fs = require('fs');
  const policyPath = process.env.BLACKBOX_SANDBOX_POLICY;
  if (!policyPath || !fs.existsSync(policyPath)) { /* no policy: allow */ }
  else {
    const policy = JSON.parse(fs.readFileSync(policyPath, 'utf8'));
    const childProcess = require('child_process');
    const net = require('net');
    const warn = (m) => console.error('BLACKBOX SHIM: ' + m);
    if (!policy.spawn && childProcess && childProcess.ChildProcess) {
      const origSpawn = childProcess.ChildProcess.prototype.spawn;
      childProcess.ChildProcess.prototype.spawn = function () {
        warn('process.spawn denied by manifest (BLACKBOX_SANDBOX_POLICY)');
        this.emit('error', new Error('spawn denied'));
        return false;
      };
      childProcess.spawn = function () { warn('process.spawn denied by manifest'); return {}; };
    }
    if (!policy.network && net && net.Socket) {
      const origConnect = net.Socket.prototype.connect;
      net.Socket.prototype.connect = function (...args) {
        let host = '';
        if (typeof args[0] === 'object' && args[0]) host = args[0].host || '';
        else if (Array.isArray(args[0])) host = args[0][0] || '';
        else if (typeof args[0] === 'string') host = args[0];
        if (host) {
          const allow = (policy.network_allow || []).some((pattern) => {
            return pattern.startsWith('*.')
              ? host.endsWith(pattern.slice(2)) || host === pattern.slice(2)
              : host === pattern;
          });
          if (!allow) {
            warn('network access denied (manifest): ' + host);
            process.nextTick(() => { try { this.destroy(); } catch (e) {} });
            return this;
          }
        }
        return origConnect.apply(this, args);
      };
    }
  }
} catch (e) { /* shim never crashes the app */ }
"#;

/// Return a shim payload by name, if embedded.
pub fn shim_payload(name: &str) -> Option<String> {
    match name {
        "sitecustomize.py" => Some(SHIM_SITECUSTOMIZE.to_string()),
        "netmatch.py" => Some(SHIM_NETMATCH.to_string()),
        "node_guard.js" => Some(NODE_GUARD_JS.to_string()),
        _ => None,
    }
}

/// Files of an init template: (relpath, content).
pub fn template_files(template: &str) -> Result<Vec<(String, &'static str)>, crate::error::BlackboxError> {
    let files: Vec<(String, &str)> = match template {
        "hello" => vec![
            ("blackbox.yaml".into(), HELLO_BLACKBOX_YAML),
            ("requirements.txt".into(), HELLO_REQUIREMENTS),
            ("src/main.py".into(), HELLO_MAIN_PY),
        ],
        "datasift" => vec![
            ("blackbox.yaml".into(), DATASIFT_BLACKBOX_YAML),
            ("requirements.txt".into(), DATASIFT_REQUIREMENTS),
            ("src/main.py".into(), DATASIFT_MAIN_PY),
            ("src/sample.csv".into(), DATASIFT_SAMPLE_CSV),
        ],
        "node" => vec![
            ("blackbox.yaml".into(), NODE_BLACKBOX_YAML),
            ("package.json".into(), NODE_PACKAGE_JSON),
            ("src/index.js".into(), NODE_MAIN_JS),
        ],
        _ => {
            return Err(crate::error::BlackboxError::new(format!("Unknown template '{}'.", template))
                .with_try("Available templates: hello, datasift, node"));
        }
    };
    let owned: Vec<(String, &'static str)> = files.into_iter().map(|(a, b)| (a, b)).collect();
    Ok(owned)
}
