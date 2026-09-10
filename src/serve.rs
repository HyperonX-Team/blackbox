//! Tiny HTTP client + LAN object-store mirror.
//!
//! The mirror (`blackbox serve`) exposes content-addressed objects by digest
//! so thin packages can be run on machines that never saw the pack machine.
//! `blackbox fetch/run` pulls objects through the same client used for
//! runtime and pip downloads - one code path for everything.

use crate::error::BlackboxError;
use crate::storage::CAS;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

pub fn http_get(url: &str) -> Result<Vec<u8>, String> {
    http_get_with_timeout(url, 60)
}

pub fn http_get_with_timeout(url: &str, timeout_secs: u64) -> Result<Vec<u8>, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(timeout_secs))
        .build();
    let resp = agent
        .get(url)
        .call()
        .map_err(|e| format!("{}", e))?;
    let mut out = Vec::new();
    resp.into_reader()
        .read_to_end(&mut out)
        .map_err(|e| format!("{}", e))?;
    Ok(out)
}

/// POST bytes to a mirror endpoint (used by `blackbox publish`).
pub fn http_put(url: &str, body: &[u8]) -> Result<(), String> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(120)).build();
    agent
        .put(url)
        .send_bytes(body)
        .map(|_| ())
        .map_err(|e| format!("{}", e))
}

#[derive(Clone)]
pub struct ServeOptions {
    pub bind: String,
    pub port: u16,
    pub allow_upload: bool,
    pub quiet: bool,
}

/// Serve the CAS (and optionally accept PUTs) on a dedicated thread.
/// Returns the serving address.
pub fn serve(options: ServeOptions) -> Result<String, String> {
    let cas = CAS::default();
    let addr = format!("{}:{}", options.bind, options.port);
    let listener = TcpListener::bind(&addr).map_err(|e| format!("Could not bind {}: {}", addr, e))?;
    let actual = listener
        .local_addr()
        .map(|a| format!("http://{}", a))
        .map_err(|e| format!("{}", e))?;
    let allow_upload = options.allow_upload;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let clone_cas = cas.clone();
                let allow = allow_upload;
                std::thread::spawn(move || {
                    let _ = handle_connection(stream, &clone_cas, allow);
                });
            }
        }
    });
    Ok(actual)
}

fn handle_connection(mut stream: TcpStream, cas: &CAS, allow_upload: bool) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf)?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]).to_string();
    let _ = &request;
    let lines: Vec<String> = request.lines().map(|l| l.to_string()).collect();
    let request_line = lines.first().cloned().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let content_length: usize = lines
        .iter()
        .find_map(|l| {
            let lower = l.to_lowercase();
            lower.strip_prefix("content-length:").and_then(|v| v.trim().parse().ok())
        })
        .unwrap_or(0);

    let resp: Vec<u8> = if method == "GET" {
        if let Some(hex) = path.strip_prefix("/objects/").or_else(|| path.strip_prefix("/objects")) {
            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                let p = cas.object_path(hex);
                if p.is_file() {
                    match std::fs::read(&p) {
                        Ok(data) => http_response(200, "application/octet-stream", &data),
                        Err(_) => http_response(404, "text/plain", b"unreadable"),
                    }
                } else {
                    http_response(404, "text/plain", b"object not found: try pin it on the publisher machine")
                }
            } else {
                http_response(400, "text/plain", b"bad digest")
            }
        } else if path == "/" || path == "/info" {
            let stats = cas.stats().unwrap_or_default();
            let text = format!(
                "BLACKBOX object mirror\nobjects: {}\nbytes: {}\nPUT {}allowed\n",
                stats.get("objects").copied().unwrap_or(0),
                stats.get("bytes").copied().unwrap_or(0),
                if allow_upload { "" } else { "not " },
            );
            http_response(200, "text/plain", text.as_bytes())
        } else {
            http_response(404, "text/plain", b"unknown path")
        }
    } else if method == "PUT" && allow_upload {
        if let Some(hex) = path.strip_prefix("/objects/").or_else(|| path.strip_prefix("/objects")) {
            if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
                http_response(400, "text/plain", b"bad digest")
            } else {
                let body = read_body(&mut stream, &buf[..n], content_length);
                let digest = crate::deterministic::sha256_bytes(&body);
                if digest == hex {
                    let _ = cas.put_bytes(&body);
                    http_response(200, "text/plain", b"stored")
                } else {
                    http_response(409, "text/plain", b"body digest mismatch")
                }
            }
        } else {
            http_response(404, "text/plain", b"unknown path")
        }
    } else {
        http_response(405, "text/plain", b"method not allowed")
    };
    let _ = stream.write_all(&resp);
    let _ = stream.flush();
    Ok(())
}

fn read_body(stream: &mut TcpStream, buf: &[u8], content_length: usize) -> Vec<u8> {
    let needle = b"\r\n\r\n";
    let header_end = buf.windows(4).position(|w| w == needle).map(|i| i + 4).unwrap_or(buf.len());
    let body_start = header_end.min(buf.len());
    let mut body = buf[body_start..].to_vec();
    while body.len() < content_length {
        let mut chunk = [0u8; 65536];
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(m) => body.extend_from_slice(&chunk[..m]),
        }
    }
    body.truncate(content_length);
    body
}

fn http_response(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        _ => "Unknown",
    };
    let mut out = Vec::new();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status,
        reason,
        content_type,
        body.len()
    );
    out.extend_from_slice(head.as_bytes());
    out.extend_from_slice(body);
    out
}

/// Publish a full package to a mirror: PUT every layer object referenced by
/// the package's layers.json. Returns (mirror_prefix, pushed_count).
pub fn publish_package(mirror_base: &str, pkg_path: &Path) -> Result<(String, u32), BlackboxError> {
    let pkg = crate::packaging::open_package(pkg_path)?;
    let cas = CAS::default();
    let mut pushed = 0u32;
    let layers_json: serde_json::Value = pkg
        .members
        .get(crate::packaging::LAYERS_INDEX)
        .map(|v| serde_json::from_slice(v).unwrap_or(serde_json::Value::Null))
        .unwrap_or(serde_json::Value::Null);
    let mut digests: Vec<String> = Vec::new();
    if let Some(layers) = layers_json.get("layers").and_then(|v| v.as_array()) {
        for layer in layers {
            if let Some(d) = layer.get("digest").and_then(|v| v.as_str()) {
                digests.push(d.to_string());
            }
        }
    }
    for ref_str in digests {
        let Ok(hex) = CAS::parse(&ref_str) else {
            continue;
        };
        let obj = cas.get_path(&ref_str).ok();
        let data = obj.and_then(|p| std::fs::read(p).ok());
        if let Some(data) = data {
            let url = format!("{}/objects/{}", mirror_base.trim_end_matches('/'), hex);
            match http_put(&url, &data) {
                Ok(()) => pushed += 1,
                Err(e) => {
                    return Err(BlackboxError::new(format!("Publish failed for {}: {}", hex, e)));
                }
            }
        }
    }
    Ok((mirror_base.to_string(), pushed))
}
