"""blackbox command-line interface."""

import argparse
import sys

from blackbox import __version__
from blackbox.cli import commands
from blackbox.errors import BlackboxError, render_error
from blackbox.storage import paths


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="blackbox",
        description="BLACKBOX - Download a machine. Pack an application with its runtime, "
                    "dependencies, interface and permissions into one portable .blackbox file.",
    )
    p.add_argument("--version", action="version", version=f"blackbox {__version__}")
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("init", help="create a new BLACKBOX project")
    sp.add_argument("name")
    sp.add_argument("--template", choices=["hello", "datasift", "node"], default="hello")
    sp.add_argument("--python", dest="pyver", default="3.12")

    sp = sub.add_parser("pack", help="build a .blackbox package from a project directory")
    sp.add_argument("path", nargs="?", default=".")
    sp.add_argument("-o", "--output", default=None)
    sp.add_argument("--target", default=None,
                    help="cross-pack for a platform triple (e.g. x86_64-unknown-linux-gnu)")
    sp.add_argument("--watch", action="store_true",
                    help="stay running: re-pack whenever a source file changes")
    sp.add_argument("--run", action="store_true",
                    help="with --watch: also (re)start the app after each re-pack")

    sp = sub.add_parser("run", help="run a .blackbox package (options before the package; "
                                    "app arguments after --)")
    sp.add_argument("--work", default=None, help="work directory (input/ output/ live here)")
    sp.add_argument("--input", action="append", default=[], help="files to copy into the package's input dir")
    sp.add_argument("--yes", action="store_true", help="skip the permission confirmation prompt")
    sp.add_argument("--data", action="store_true",
                    help="give the package a persistent data dir (BLACKBOX_DATA env)")
    sp.add_argument("--log", action="store_true", help="tee app output to ~/.blackbox/logs/")
    sp.add_argument("--entry", default=None, help="run a named subcommand from the manifest's entrypoints")
    sp.add_argument("package")
    sp.add_argument("app_args", nargs=argparse.REMAINDER, help="passed through to the app after --")

    sp = sub.add_parser("inspect", help="show a package's manifest and layers")
    sp.add_argument("package")

    sp = sub.add_parser("verify", help="verify integrity and signature")
    sp.add_argument("package")

    sp = sub.add_parser("unpack", help="extract a package for inspection")
    sp.add_argument("package")
    sp.add_argument("dest", nargs="?", default=None)

    sp = sub.add_parser("list", help="list cached packages")

    sp = sub.add_parser("cache", help="show cache statistics")
    sp.add_argument("--clear", action="store_true", help="delete all cached objects/layers")
    sp.add_argument("--check", action="store_true", help="verify cached object digests")

    sp = sub.add_parser("gc", help="clean unreferenced cache objects, stale layers and tmp files")
    sp.add_argument("--apply", action="store_true", help="delete (default: dry-run)")
    sp.add_argument("--older-than", type=int, default=None, metavar="DAYS",
                    help="also drop layers unused for N days")

    sp = sub.add_parser("doctor", help="diagnose the local BLACKBOX installation")
    sp.add_argument("--fix", action="store_true", help="repair: ensure dirs, purge corrupt objects, refresh shim")

    sp = sub.add_parser("explain", help="show what a package would access, without running it")
    sp.add_argument("package")

    sp = sub.add_parser("diff", help="compare two .blackbox packages")
    sp.add_argument("package_a")
    sp.add_argument("package_b")

    sp = sub.add_parser("audit", help="statically scan a package's contents before running it")
    sp.add_argument("package")

    sp = sub.add_parser("seal", help="encrypt a secrets file into a package")
    sp.add_argument("package")
    sp.add_argument("--secrets", required=True, help="KEY=VALUE file to seal")
    sp.add_argument("--to", default=None, help="recipient's *.seal.pub.pem")
    sp.add_argument("--key", default=None, help="or: a key name created by 'blackbox keygen'")

    sp = sub.add_parser("shell", help="open an interactive shell inside a package's environment")
    sp.add_argument("package")
    sp.add_argument("--work", default=None)
    sp.add_argument("--yes", action="store_true")
    sp.add_argument("--data", action="store_true")

    sp = sub.add_parser("dev", help="run a project directory with package-like isolation (no pack)")
    sp.add_argument("path")
    sp.add_argument("app_args", nargs=argparse.REMAINDER)

    sp = sub.add_parser("service", help="keep a package running: logon autostart + auto-restart")
    ssub = sp.add_subparsers(dest="service_cmd")
    si = ssub.add_parser("install", help="register a package as a user service")
    si.add_argument("package")
    si.add_argument("--name", required=True)
    si.add_argument("--args", default="", help="extra args passed to 'blackbox run'")
    su = ssub.add_parser("uninstall", help="remove a registered service")
    su.add_argument("name")
    ssub.add_parser("list", help="list registered services")
    ss = ssub.add_parser("status", help="tail a service's log")
    ss.add_argument("name")

    sp = sub.add_parser("upgrade", help="swap a package for a newer, signed one (atomic)")
    sp.add_argument("package")
    sp.add_argument("--from", dest="from_url", required=True, help="URL or path of the candidate .blackbox")
    sp.add_argument("--yes", action="store_true", help="accept a valid-but-untrusted signature")

    sp = sub.add_parser("install", help="register .blackbox double-click + a Start Menu launcher")
    sp.add_argument("package", nargs="?", default=None)
    sp.add_argument("--no-assoc", action="store_true", help="skip the file association")

    sp = sub.add_parser("export-docker", help="emit a Dockerfile + build context from a package")
    sp.add_argument("package")
    sp.add_argument("--out", default=None)

    sp = sub.add_parser("bench", help="measure cold vs warm prepare/run cost of a package")
    sp.add_argument("package")
    sp.add_argument("--runs", type=int, default=1)

    sp = sub.add_parser("keygen", help="create an Ed25519 signing key (+ X25519 seal key)")
    sp.add_argument("name")
    sp.add_argument("--publisher", default=None)

    sp = sub.add_parser("sign", help="sign a package")
    sp.add_argument("package")
    sp.add_argument("--key", required=True)

    sp = sub.add_parser("trust", help="pin a publisher public key")
    sp.add_argument("pubkey_file")
    sp.add_argument("--publisher", required=True)

    sp = sub.add_parser("runtime", help="manage BLACKBOX runtimes")
    rsub = sp.add_subparsers(dest="runtime_cmd")
    rimp = rsub.add_parser("import", help="install a runtime from a local python-build-standalone tarball")
    rimp.add_argument("tarball")
    rls = rsub.add_parser("list", help="list installed runtimes")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.cmd:
        parser.print_help()
        return 2
    paths.ensure_home()
    try:
        return _dispatch(args)
    except BlackboxError as e:
        print(render_error(e), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nBLACKBOX: interrupted.", file=sys.stderr)
        return 130


def _dispatch(args) -> int:
    return {
        "init": commands.cmd_init,
        "pack": commands.cmd_pack,
        "run": commands.cmd_run,
        "inspect": commands.cmd_inspect,
        "verify": commands.cmd_verify,
        "unpack": commands.cmd_unpack,
        "list": commands.cmd_list,
        "cache": commands.cmd_cache,
        "gc": commands.cmd_gc,
        "doctor": commands.cmd_doctor,
        "explain": commands.cmd_explain,
        "diff": commands.cmd_diff,
        "audit": commands.cmd_audit,
        "seal": commands.cmd_seal,
        "upgrade": commands.cmd_upgrade,
        "shell": commands.cmd_shell,
        "dev": commands.cmd_dev,
        "service": commands.cmd_service,
        "install": commands.cmd_install,
        "export-docker": commands.cmd_export_docker,
        "bench": commands.cmd_bench,
        "keygen": commands.cmd_keygen,
        "sign": commands.cmd_sign,
        "trust": commands.cmd_trust,
        "runtime": commands.cmd_runtime,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
