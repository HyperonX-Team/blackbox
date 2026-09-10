//! blackbox command-line interface.

use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "blackbox", version, about = "BLACKBOX - Download a machine. Pack an application with its runtime, dependencies, interface and permissions into one portable .blackbox file.")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new BLACKBOX project
    Init {
        name: String,
        #[arg(long, default_value = "hello")]
        template: String,
        #[arg(long, default_value = "3.12")]
        python: String,
    },
    /// Build a .blackbox package from a project directory
    Pack {
        path: Option<String>,
        #[arg(short, long)]
        output: Option<String>,
        #[arg(long, help = "cross-pack for a platform triple (e.g. x86_64-unknown-linux-gnu)")]
        target: Option<String>,
        #[arg(long, help = "NEW: omit layer blobs; emit a thin package fetched from object sources")]
        thin: bool,
        #[arg(long, action = ArgAction::SetTrue, help = "stay running: re-pack whenever a source file changes")]
        watch: bool,
        #[arg(long, action = ArgAction::SetTrue, help = "with --watch: also (re)start the app after each re-pack")]
        run: bool,
    },
    /// Run a .blackbox package (options before the package; app arguments after --)
    Run {
        #[arg(long)]
        work: Option<String>,
        #[arg(long, action = ArgAction::Append, help = "files to copy into the package's input dir")]
        input: Vec<PathBuf>,
        #[arg(long, action = ArgAction::SetTrue, help = "skip the permission confirmation prompt")]
        yes: bool,
        #[arg(long, action = ArgAction::SetTrue, help = "give the package a persistent data dir")]
        data: bool,
        #[arg(long, action = ArgAction::SetTrue, help = "tee app output to ~/.blackbox/logs/")]
        log: bool,
        #[arg(long, help = "run a named subcommand from the manifest's entrypoints")]
        entry: Option<String>,
        package: String,
        #[arg(last = true)]
        app_args: Vec<String>,
    },
    /// Show a package's manifest and layers
    Inspect { package: String },
    /// Verify integrity and signature
    Verify { package: String },
    /// Extract a package for inspection
    Unpack { package: String, dest: Option<String> },
    /// List cached packages
    List,
    /// Show cache statistics
    Cache {
        #[arg(long, action = ArgAction::SetTrue)]
        clear: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        check: bool,
    },
    /// Clean unreferenced cache objects, stale layers and tmp files
    Gc {
        #[arg(long, action = ArgAction::SetTrue, help = "delete (default: dry-run)")]
        apply: bool,
        #[arg(long, help = "also drop layers unused for N days")]
        older_than: Option<i64>,
    },
    /// Diagnose the local BLACKBOX installation
    Doctor {
        #[arg(long, action = ArgAction::SetTrue)]
        fix: bool,
    },
    /// Show what a package would access, without running it
    Explain { package: String },
    /// Compare two .blackbox packages
    Diff { package_a: String, package_b: String },
    /// Statically scan a package's contents before running it
    Audit { package: String },
    /// Encrypt a secrets file into a package
    Seal {
        package: String,
        #[arg(long, required = true, help = "KEY=VALUE file to seal")]
        secrets: String,
        #[arg(long, help = "recipient's *.seal.pub.pem")]
        to: Option<String>,
        #[arg(long, help = "or: a key name created by 'blackbox keygen'")]
        key: Option<String>,
    },
    /// NEW: encrypt all private layer members of a package to a recipient
    Encrypt {
        package: String,
        #[arg(long, help = "recipient's *.seal.pub.pem")]
        to: Option<String>,
        #[arg(long)]
        key: Option<String>,
    },
    /// NEW: decrypt a .sealed.blackbox into a fresh plain package
    Decrypt {
        package: String,
        #[arg(long)]
        out: Option<String>,
    },
    /// Open an interactive shell inside a package's environment
    Shell {
        package: String,
        #[arg(long)]
        work: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        data: bool,
    },
    /// Run a project directory with package-like isolation (no pack)
    Dev {
        path: String,
        #[arg(last = true)]
        app_args: Vec<String>,
    },
    /// Keep a package running: logon autostart + auto-restart
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
    /// Swap a package for a newer, signed one (atomic)
    Upgrade {
        package: String,
        #[arg(long)]
        from_url: String,
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
    },
    /// Register .blackbox double-click + a Start Menu launcher
    Install {
        package: Option<String>,
        #[arg(long, action = ArgAction::SetTrue)]
        no_assoc: bool,
    },
    /// Emit a Dockerfile + build context from a package
    ExportDocker {
        package: String,
        #[arg(long)]
        out: Option<String>,
    },
    /// Measure cold vs warm prepare/run cost of a package
    Bench {
        package: String,
        #[arg(long, default_value_t = 1)]
        runs: u32,
    },
    /// Create an Ed25519 signing key (+ X25519 seal key)
    Keygen {
        name: String,
        #[arg(long)]
        publisher: Option<String>,
    },
    /// Sign a package
    Sign { package: String, #[arg(long, required = true)] key: String },
    /// Pin a publisher public key
    Trust {
        pubkey_file: String,
        #[arg(long, required = true)]
        publisher: String,
    },
    /// Manage BLACKBOX runtimes
    Runtime {
        #[command(subcommand)]
        cmd: RuntimeCmd,
    },
    /// NEW: serve the local object store as a LAN mirror (thin packages)
    Serve {
        #[arg(long, default_value_t = 8787)]
        port: u16,
        #[arg(long, action = ArgAction::SetTrue, help = "accept PUT object uploads (publish)")]
        allow_upload: bool,
        #[arg(long, action = ArgAction::SetTrue)]
        quiet: bool,
    },
    /// NEW: fetch a thin package's layers from objects/mirrors into a full one
    Fetch {
        package: String,
        #[arg(long, help = "mirror base URL (also read from BLACKBOX_OBJECT_URLS)")]
        mirror: Option<String>,
    },
    /// NEW: push a package's layer objects to a running mirror
    Publish { package: String, #[arg(long, required = true)] mirror: String },
    /// NEW: build a composite pipeline package out of staged .blackbox projects
    Compose {
        #[arg(long, required = true)]
        manifest: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        out: Option<String>,
    },
    /// NEW: emit an SBOM (CycloneDX or SPDX) for a package
    Sbom {
        package: String,
        #[arg(long, default_value = "spdx", help = "spdx | cyclonedx")]
        format: String,
    },
    /// NEW: update the blackbox binary from a signed update payload
    SelfUpdate {
        url: String,
        #[arg(long, action = ArgAction::SetTrue)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ServiceCmd {
    /// Register a package as a user service
    Install {
        package: String,
        #[arg(long, required = true)]
        name: String,
        #[arg(long, default_value = "")]
        args: String,
    },
    /// Remove a registered service
    Uninstall { name: String },
    /// List registered services
    List,
    /// Tail a service's log
    Status { name: String },
}

#[derive(Subcommand)]
enum RuntimeCmd {
    /// Install a runtime from a local python-build-standalone tarball
    Import { tarball: String },
    /// List installed runtimes
    List,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.cmd {
        Commands::Init { name, template, python } => {
            blackbox_runtime::commands::cmd_init(&name, &template, &python)
        }
        Commands::Pack { path, output, target, thin, watch, run } => {
            let path = path.unwrap_or_else(|| ".".to_string());
            if watch {
                let code = blackbox_runtime::commands::cmd_pack_watch(&path, output.clone(), target.clone(), thin, run);
                std::process::exit(code);
            }
            blackbox_runtime::commands::cmd_pack(&path, output, target, thin)
        }
        Commands::Run { work, input, yes, data, log, entry, package, app_args } => {
            let inputs = input
                .iter()
                .map(|p| blackbox_runtime::commands::FileArg {
                    name: p.file_name().map(|f| f.to_string_lossy().to_string()).unwrap_or_else(|| p.to_string_lossy().to_string()),
                })
                .collect();
            blackbox_runtime::commands::cmd_run(&package, work, inputs, yes, data, log, entry, app_args)
        }
        Commands::Inspect { package } => blackbox_runtime::commands::cmd_inspect(&package),
        Commands::Verify { package } => blackbox_runtime::commands::cmd_verify(&package),
        Commands::Unpack { package, dest } => blackbox_runtime::commands::cmd_unpack(&package, dest),
        Commands::List => blackbox_runtime::commands::cmd_list(),
        Commands::Cache { clear, check } => blackbox_runtime::commands::cmd_cache(clear, check),
        Commands::Gc { apply, older_than } => blackbox_runtime::commands::cmd_gc(!apply, older_than),
        Commands::Doctor { fix } => blackbox_runtime::commands::cmd_doctor(fix),
        Commands::Explain { package } => blackbox_runtime::commands::cmd_explain(&package),
        Commands::Diff { package_a, package_b } => blackbox_runtime::commands::cmd_diff(&package_a, &package_b),
        Commands::Audit { package } => blackbox_runtime::commands::cmd_audit(&package),
        Commands::Seal { package, secrets, to, key } => {
            blackbox_runtime::commands::cmd_seal(&package, &secrets, to, key)
        }
        Commands::Encrypt { package, to, key } => blackbox_runtime::commands::cmd_encrypt(&package, to, key),
        Commands::Decrypt { package, out } => blackbox_runtime::commands::cmd_decrypt(&package, out),
        Commands::Shell { package, work, yes, data } => {
            blackbox_runtime::commands::cmd_shell(&package, work, yes, data)
        }
        Commands::Dev { path, app_args } => blackbox_runtime::commands::cmd_dev(&path, app_args),
        Commands::Service { cmd } => match cmd {
            ServiceCmd::Install { package, name, args } => {
                blackbox_runtime::commands::cmd_service_install(&package, &name, &args)
            }
            ServiceCmd::Uninstall { name } => blackbox_runtime::commands::cmd_service_uninstall(&name),
            ServiceCmd::List => blackbox_runtime::commands::cmd_service_list(),
            ServiceCmd::Status { name } => blackbox_runtime::commands::cmd_service_status(&name),
        },
        Commands::Upgrade { package, from_url, yes } => {
            blackbox_runtime::commands::cmd_upgrade(&package, &from_url, yes)
        }
        Commands::Install { package, no_assoc } => {
            blackbox_runtime::commands::cmd_install(package.as_deref(), no_assoc)
        }
        Commands::ExportDocker { package, out } => {
            blackbox_runtime::commands::cmd_export_docker(&package, out)
        }
        Commands::Bench { package, runs } => blackbox_runtime::commands::cmd_bench(&package, runs),
        Commands::Keygen { name, publisher } => blackbox_runtime::commands::cmd_keygen(&name, publisher.as_deref()),
        Commands::Sign { package, key } => blackbox_runtime::commands::cmd_sign(&package, &key),
        Commands::Trust { pubkey_file, publisher } => {
            blackbox_runtime::commands::cmd_trust(&pubkey_file, &publisher)
        }
        Commands::Runtime { cmd } => match cmd {
            RuntimeCmd::Import { tarball } => blackbox_runtime::commands::cmd_runtime_import(&tarball),
            RuntimeCmd::List => blackbox_runtime::commands::cmd_runtime_list(),
        },
        Commands::Serve { port, allow_upload, quiet } => {
            blackbox_runtime::commands::cmd_serve(port, allow_upload, quiet)
        }
        Commands::Fetch { package, mirror } => blackbox_runtime::commands::cmd_fetch(&package, mirror),
        Commands::Publish { package, mirror } => blackbox_runtime::commands::cmd_publish(&package, &mirror),
        Commands::Compose { manifest, name, out } => {
            blackbox_runtime::commands::cmd_compose(&manifest, name.as_deref().unwrap_or(""), out)
        }
        Commands::Sbom { package, format } => blackbox_runtime::commands::cmd_sbom(&package, &format),
        Commands::SelfUpdate { url, yes } => blackbox_runtime::commands::cmd_self_update(&url, yes),
    };
    std::process::exit(code);
}
