//! BLACKBOX core library.
//!
//! A `.blackbox` file is a portable object: a program plus its runtime,
//! dependencies, interface, permissions and data contract, reproducible by
//! hash, runnable with no host setup.
//!
//! The Rust rewrite of the blackbox Python MVP: same package format
//! (deterministic ZIP: manifest.json, blackbox.lock, layer tars, checksums,
//! optional signature), same provider extension model, plus new capabilities
//! (WASM + Rust runtimes, multi-target fat packages, thin packages with
//! content mirrors, composite pipelines, whole-package encryption, SBOM
//! export and signed binary self-update).

pub mod commands;
pub mod crypto;
pub mod dependency;
pub mod deterministic;
pub mod error;
pub mod manifest;
pub mod packaging;
pub mod platform;
pub mod runtime;
pub mod sandbox;
pub mod serve;
pub mod storage;
pub mod templates;

pub const VERSION: &str = "0.2.0";
