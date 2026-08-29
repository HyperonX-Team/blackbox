"""CLI command implementations."""

import json
import os
import shutil
import sys

from blackbox import __version__, deterministic
from blackbox.crypto import signing
from blackbox.errors import BlackboxError
from blackbox.manifest import summarize
from blackbox.packaging import builder, format as fmt, reader
from blackbox.runtime import runner
from blackbox.runtime.manager import RuntimeManager
from blackbox.sandbox import jail
from blackbox.storage import paths
from blackbox.storage.cas import CAS
from blackbox import platform as bb_platform


# ---------- init ----------

def cmd_init(args) -> int:
    name = args.name
    target = os.path.abspath(name)
    if os.path.exists(target):
        raise BlackboxError(f"Directory '{name}' already exists.")
    templates = os.path.join(os.path.dirname(__file__), "templates", args.template)
    if not os.path.isdir(templates):
        raise BlackboxError(f"Unknown template '{args.template}'.")
    shutil.copytree(templates, target)
    mpath = os.path.join(target, "blackbox.yaml")
    manifest_text = open(mpath, encoding="utf-8").read().replace("blackbox-template", name.lower().replace(" ", "-")).replace('version: "3.12"', f'version: "{args.pyver}"')
    with open(mpath, "w", encoding="utf-8", newline="\n") as f:
        f.write(manifest_text)
    print(f"BLACKBOX project created: {name}/")
    print()
    print("Next steps:")
    print(f"  cd {name}")
    print("  blackbox pack")
    print(f"  blackbox run {name}.blackbox")
    return 0


# ---------- pack ----------

def cmd_pack(args) -> int:
    out = builder.pack(args.path, args.output, target=args.target,
                       progress=lambda s: print("  " + s))
    print(f"PACKED  {out}")
    return 0


# ---------- run ----------

def cmd_run(args) -> int:
    pkg = reader.open_package(args.package)
    sig = signing.verify_package(pkg)
    work = args.work or os.path.join(os.getcwd(), f"{pkg.manifest['name']}-work")
    _consent_gate(pkg, sig, assume_yes=args.yes or ("--yes" in (args.app_args or [])))
    for src in args.input:
        if not os.path.isfile(src):
            raise BlackboxError(f"Input file not found: {src}",
                                try_hint="Pass paths to existing files: blackbox run pkg --input data.csv")
        os.makedirs(os.path.join(work, "input"), exist_ok=True)
        dst = os.path.join(work, "input", os.path.basename(src))
        if os.path.abspath(src) != os.path.abspath(dst):
            shutil.copyfile(src, dst)
    ctx = reader.prepare_run(pkg, work)
    app_args = [a for a in (args.app_args or []) if a not in ("--", "--yes")]
    rc = runner.execute(ctx, app_args)
    if rc != 0:
        print(f"\nBLACKBOX: {pkg.manifest['name']} exited with code {rc}.", file=sys.stderr)
    else:
        out_dir = os.path.join(work, "output")
        if os.path.isdir(out_dir) and os.listdir(out_dir):
            print(f"\nBLACKBOX: output written to {out_dir}")
    return rc


def _consent_gate(pkg, sig, *, assume_yes=False):
    """Security UX: show what the package requests before first run (docs/security.md)."""
    m = pkg.manifest
    state_line = {
        "unsigned": "Signature:   none",
        "valid": f"Signature:   VALID (publisher: {sig['publisher']})",
        "trusted": f"Signature:   VALID - TRUSTED publisher: {sig['publisher']}",
        "invalid": "Signature:   INVALID - contents changed since signing!",
    }[sig["state"]]
    if sig["state"] == "invalid":
        raise BlackboxError("Refusing to run: the package changed after it was signed.",
                            try_hint="blackbox verify " + pkg.path)
    registry = paths.home() / "approvals.json"
    approvals = {}
    if registry.exists():
        try:
            approvals = json.loads(registry.read_text())
        except json.JSONDecodeError:
            approvals = {}
    if approvals.get(pkg.content_digest) == "allow":
        return
    if assume_yes or not sys.stdin.isatty():
        return
    p = m["permissions"]
    fs_mode = "restricted" if (p["filesystem"]["read"] or p["filesystem"]["write"]) else "no filesystem access"
    print()
    print("BLACKBOX" + " " * 40)
    print(f"{m['description'] or m['name']}")
    print()
    print(f"Name:        {m['name']} {m['version']}")
    print(f"Publisher:   {m['publisher']}")
    print(state_line)
    print()
    print("Requests:")
    print()
    print("  Filesystem:")
    print(f"    {'+' if p['filesystem']['read'] else '-'} read:   {', '.join(p['filesystem']['read']) or 'none'}")
    print(f"    {'+' if p['filesystem']['write'] else '-'} write:  {', '.join(p['filesystem']['write']) or 'none'}")
    print()
    print("  Network:")
    print(f"    {'+' if p['network']['enabled'] else '-'} {'enabled' if p['network']['enabled'] else 'disabled'}")
    print()
    print("  Host execution:")
    print(f"    {'+' if p['process']['spawn'] else '-'} process spawning: {'allowed' if p['process']['spawn'] else 'restricted'}")
    print()
    try:
        answer = input("Run this BLACKBOX? [y/N] ").strip().lower()
    except EOFError:
        answer = ""
    if answer in ("y", "yes"):
        approvals[pkg.content_digest] = "allow"
        registry.write_text(json.dumps(approvals, indent=2, sort_keys=True))
        return
    raise BlackboxError("Not run: the requested permissions were not approved.",
                        try_hint="Re-run with --yes to approve these permissions for this package digest.",
                        changes_made=False)


# ---------- inspect ----------

def cmd_inspect(args) -> int:
    pkg = reader.open_package(args.package)
    m = pkg.manifest
    print(summarize(m))
    try:
        lock = __import__("yaml").safe_load(pkg.members[fmt.LOCK])
    except Exception:
        lock = {"packages": []}
    pkgs = lock.get("packages", [])
    print("")
    print(f"Dependencies ({len(pkgs)}):")
    for p in pkgs:
        print(f"  {p['name']}  {p['version']}")
    print("")
    print("Layers:")
    layers = json.loads(pkg.members[fmt.LAYERS_INDEX])["layers"]
    for layer in layers:
        print(f"  {layer['kind']:<14} {layer['digest'][:23]}  {deterministic.human_size(layer['bytes'])}")
    sig = signing.verify_package(pkg)
    print("")
    print(f"Integrity:   OK (checksums verified)")
    state = {"unsigned": "unsigned", "valid": f"signature VALID ({sig['publisher']})",
             "trusted": f"signature VALID, publisher TRUSTED ({sig['publisher']})",
             "invalid": "signature INVALID"}[sig["state"]]
    print(f"Signature:   {state}")
    print(f"Package digest: {pkg.content_digest}")
    return 0


# ---------- verify ----------

def cmd_verify(args) -> int:
    try:
        pkg = reader.open_package(args.package)
    except BlackboxError:
        print("Integrity:   FAILED", file=sys.stderr)
        raise
    print("Integrity:   OK")
    for name in sorted(pkg.checksums):
        print(f"  {name:<24} sha256:{pkg.checksums[name][:16]}...")
    sig = signing.verify_package(pkg)
    label = {"unsigned": "unsigned", "valid": "VALID", "trusted": f"VALID - trusted publisher: {sig['publisher']}",
             "invalid": f"INVALID: {sig.get('reason', '')}"}[sig["state"]]
    print(f"Signature:   {label}")
    print(f"Content digest: {pkg.content_digest}")
    return 0 if sig["state"] != "invalid" else 1


# ---------- unpack ----------

def cmd_unpack(args) -> int:
    pkg = reader.open_package(args.package)
    dest = args.dest or f"{pkg.manifest['name']}-unpacked"
    reader.unpack_all(pkg, dest)
    print(f"Unpacked to {os.path.abspath(str(dest))}/")
    print("  blackbox.yaml (manifest.json)   lockfile (blackbox.lock)   checksums.json")
    print("  application/  and  dependencies/  (expanded layers)")
    return 0


# ---------- list / cache ----------

def cmd_list(args) -> int:
    layers_dir = paths.home() / "layers"
    found = False
    if layers_dir.is_dir():
        for d in sorted(layers_dir.iterdir()):
            kind = next((k for k in ("application", "dependencies") if (d / k).is_dir()), None)
            if kind:
                n = sum(len(fs) for _, _, fs in os.walk(d / kind))
                print(f"  layer {d.name[:25]:<27} {kind:<13} files={n}")
                found = True
    if not found:
        print("No cached layers yet. Run 'blackbox pack' or 'blackbox run'.")
    return 0


def cmd_cache(args) -> int:
    cas = CAS()
    if args.check:
        corrupt = cas.check_all()
        if corrupt:
            print("Corrupted objects detected:", file=sys.stderr)
            for c in corrupt:
                print("  " + c, file=sys.stderr)
            return 1
        print("Cache integrity: OK")
        return 0
    if args.clear:
        cas.clear()
        shutil.rmtree(paths.home() / "layers", ignore_errors=True)
        print("Cache cleared (runtimes kept; use 'blackbox runtime' commands for those).")
        return 0
    st = cas.stats()
    layers_dir = paths.home() / "layers"
    n_layers = sum(1 for d in layers_dir.iterdir() if d.is_dir()) if layers_dir.is_dir() else 0
    print(f"CACHE  {paths.home()}")
    print(f"  objects:      {st['objects']}")
    print(f"  stored bytes: {deterministic.human_size(st['bytes'])}")
    print(f"  layers:       {n_layers}")
    rt = paths.home() / "runtimes"
    for rtype in ("python", "node"):
        root = rt / rtype
        if root.is_dir():
            for fam in sorted(root.iterdir()):
                if not fam.is_dir():
                    continue
                for tgt in sorted(fam.iterdir()):
                    print(f"  runtime:      {rtype} {fam.name} ({tgt.name})")
    return 0


# ---------- doctor ----------

def cmd_doctor(args) -> int:
    print(f"BLACKBOX {__version__} - doctor")
    print()
    ok = True
    print(f"  platform:            {bb_platform.current_triple()}")
    try:
        paths.ensure_home()
        probe = paths.home() / "tmp" / ".probe"
        probe.write_text("x")
        probe.unlink()
        print(f"  home:                {paths.home()}  [writable]")
    except OSError as e:
        ok = False
        print(f"  home:                NOT WRITABLE ({e})")
    host_py = f"{sys.version_info.major}.{sys.version_info.minor}"
    print(f"  host python:         {sys.version.split()[0]} (not used by packages)")
    mgr = RuntimeManager()
    for rtype, fam, present in mgr.installed():
        state = "installed" if present else "not cached (downloaded on first use)"
        print(f"  runtime {rtype} {fam}: {state}")
    print("  runtime native:    n/a (binaries ship inside the package)")
    cap = jail.capability()
    print(f"  sandbox:             {cap}")
    if cap == "shim-only":
        print(f"                       (in-process shim; platform jail unavailable here - see docs/security.md)")
    try:
        import cryptography  # noqa
        import yaml  # noqa
        import zstandard  # noqa
        print("  libraries:           ok (yaml, cryptography, zstandard)")
    except ImportError as e:
        ok = False
        print(f"  libraries:           MISSING {e.name}")
    try:
        import urllib.request
        urllib.request.urlopen("https://pypi.org/simple/", timeout=8)
        print("  network (pypi):      reachable")
    except OSError:
        print("  network (pypi):      unreachable (offline mode: only cached packages can run)")
    print()
    print("  everything looks healthy" if ok else "  some checks FAILED - fix the items above")
    return 0 if ok else 1


# ---------- signing ----------

def cmd_keygen(args) -> int:
    r = signing.keygen(args.name, args.publisher or args.name)
    print(f"Created Ed25519 key pair '{args.name}'")
    print(f"  private: {r['private']}   (keep this secret!)")
    print(f"  public:  {r['public']}   (share this with recipients)")
    return 0


def cmd_sign(args) -> int:
    pkg = reader.open_package(args.package, verify=True)
    blob = signing.sign_package(pkg, key_name=args.key)
    signing.attach_signature(args.package, blob)
    recheck = reader.open_package(args.package)
    r = signing.verify_package(recheck)
    print(f"Signed. State: {r['state']}  publisher: {r['publisher']}")
    return 0


def cmd_trust(args) -> int:
    entry = signing.trust_key(args.pubkey_file, args.publisher)
    print(f"Trusted publisher '{entry['publisher']}' (key sha256:{entry['sha256'][:16]}...)")
    return 0


# ---------- runtime ----------

def cmd_runtime(args) -> int:
    if args.runtime_cmd == "import":
        info = RuntimeManager().import_tarball(args.tarball)
        print(f"Installed runtime python {info['full']} for {info['target']}")
        return 0
    if args.runtime_cmd == "list" or not args.runtime_cmd:
        mgr = RuntimeManager()
        for rtype, fam, present in mgr.installed():
            print(f"  {rtype} {fam}: {'installed' if present else 'not installed'}")
        return 0
    raise BlackboxError("Unknown runtime command.")
