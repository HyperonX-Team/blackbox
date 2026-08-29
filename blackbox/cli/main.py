"""blackbox command-line interface."""

import argparse
import sys

from blackbox import __version__
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

    sp = sub.add_parser("run", help="run a .blackbox package (options before the package; "
                                    "app arguments after --)")
    sp.add_argument("--work", default=None, help="work directory (input/ output/ live here)")
    sp.add_argument("--input", action="append", default=[], help="files to copy into the package's input dir")
    sp.add_argument("--yes", action="store_true", help="skip the permission confirmation prompt")
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

    sp = sub.add_parser("doctor", help="diagnose the local BLACKBOX installation")

    sp = sub.add_parser("keygen", help="create an Ed25519 signing key")
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
    from blackbox.cli import commands
    return {
        "init": commands.cmd_init,
        "pack": commands.cmd_pack,
        "run": commands.cmd_run,
        "inspect": commands.cmd_inspect,
        "verify": commands.cmd_verify,
        "unpack": commands.cmd_unpack,
        "list": commands.cmd_list,
        "cache": commands.cmd_cache,
        "doctor": commands.cmd_doctor,
        "keygen": commands.cmd_keygen,
        "sign": commands.cmd_sign,
        "trust": commands.cmd_trust,
        "runtime": commands.cmd_runtime,
    }[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
