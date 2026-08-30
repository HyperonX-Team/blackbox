"""CLI command implementations."""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from blackbox import __version__, deterministic
from blackbox.crypto import sealing, signing
from blackbox.errors import BlackboxError, render_error
from blackbox.manifest import load_manifest, summarize
from blackbox.packaging import builder, format as fmt, reader
from blackbox.runtime import runner
from blackbox.runtime.manager import RuntimeManager
from blackbox.sandbox.policy import build_policy
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
    if getattr(args, "watch", False):
        _watch_loop(args.path, args.output, run_pkg=bool(getattr(args, "run", False)), last_pkg=out)
    return 0


def _watch_snapshot(root):
    seen = {}
    base = os.path.abspath(str(root))
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in
                       ("__pycache__", "node_modules", ".git", "output", "input", ".blackbox")]
        for fn in filenames:
            if fn == "blackbox.lock":
                continue
            p = os.path.join(dirpath, fn)
            try:
                st = os.stat(p)
                seen[os.path.relpath(p, base)] = (st.st_size, st.st_mtime)
            except OSError:
                pass
    return seen


def _spawn_pkg(pkg_path):
    exe = shutil.which("blackbox") or sys.argv[0]
    return subprocess.Popen([exe, "run", str(pkg_path), "--yes"])


def _watch_loop(root, out, *, run_pkg, last_pkg):
    print(f"BLACKBOX: watching {os.path.abspath(str(root))} — Ctrl+C to stop")
    seen = _watch_snapshot(root)
    proc = None
    try:
        while True:
            time.sleep(1.0)
            now = _watch_snapshot(root)
            if now == seen:
                continue
            seen = now
            print("BLACKBOX: change detected — re-packing...")
            try:
                last_pkg = builder.pack(root, out, progress=lambda s: print("  " + s))
                print(f"PACKED  {last_pkg}")
            except BlackboxError as e:
                print(render_error(e))
                continue
            if run_pkg:
                if proc and proc.poll() is None:
                    proc.kill()
                    proc.wait()
                proc = _spawn_pkg(last_pkg)
                print(f"BLACKBOX: restarted {last_pkg}")
    except KeyboardInterrupt:
        print("\nBLACKBOX: watch stopped.")
        if proc and proc.poll() is None:
            proc.kill()


# ---------- run ----------

def cmd_run(args) -> int:
    pkg = reader.open_package(args.package)
    sig = signing.verify_package(pkg)
    work = args.work or os.path.join(os.getcwd(), f"{pkg.manifest['name']}-work")
    data_dir = None
    if getattr(args, "data", False):
        data_dir = paths.home() / "data" / pkg.package_id()
    _consent_gate(pkg, sig, assume_yes=args.yes or ("--yes" in (args.app_args or [])))
    for src in args.input:
        if not os.path.isfile(src):
            raise BlackboxError(f"Input file not found: {src}",
                                try_hint="Pass paths to existing files: blackbox run pkg --input data.csv")
        os.makedirs(os.path.join(work, "input"), exist_ok=True)
        dst = os.path.join(work, "input", os.path.basename(src))
        if os.path.abspath(src) != os.path.abspath(dst):
            shutil.copyfile(src, dst)
    ctx = reader.prepare_run(pkg, work, data_dir=data_dir)
    if getattr(args, "log", False):
        ctx.log_file = str(paths.home() / "logs" / f"{pkg.manifest['name']}.log")
    if getattr(args, "entry", None):
        ctx.entry = args.entry
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
    if fmt.SECRETS in pkg.members:
        print("Sealed secrets: present (encrypted payload — opened only with the recipient seal key)")
    print()
    print("Requests:")
    print()
    print("  Filesystem:")
    print(f"    {'+' if p['filesystem']['read'] else '-'} read:   {', '.join(p['filesystem']['read']) or 'none'}")
    print(f"    {'+' if p['filesystem']['write'] else '-'} write:  {', '.join(p['filesystem']['write']) or 'none'}")
    print()
    print("  Network:")
    print(f"    {'+' if p['network']['enabled'] else '-'} {'enabled' if p['network']['enabled'] else 'disabled'}")
    if p["network"].get("allow"):
        print(f"      allow: {', '.join(p['network']['allow'])}")
    print()
    lim = m.get("limits") or {}
    if lim:
        print("  Limits:")
        for k in sorted(lim):
            print(f"    {k}: {lim[k]}")
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
    if fmt.PROVENANCE in pkg.members:
        prov = json.loads(pkg.members[fmt.PROVENANCE])
        print("")
        print(f"Provenance: {prov.get('tool')} | host {prov.get('host')} -> target {prov.get('target')}")
        if fmt.SECRETS in pkg.members:
            print("Sealed secrets: present (encrypted payload)")
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
        net_ok = True
    except OSError:
        print("  network (pypi):      unreachable (offline mode: only cached packages can run)")
        net_ok = False

    if getattr(args, "fix", False):
        print()
        print("  --fix: repairing")
        paths.ensure_home()
        print("    home directories:  ensured")
        cas_fix = CAS()
        corrupt = cas_fix.check_all()
        for ref in corrupt:
            cas_fix.delete(ref)
        print(f"    corrupt objects:   {'removed ' + str(len(corrupt)) if corrupt else 'none'}")
        try:
            runner._shim_dir()
            print("    sandbox shim:      refreshed")
        except OSError as e:
            print(f"    sandbox shim:      could not refresh ({e})")
        if not net_ok:
            print("    runtimes:          offline — run 'blackbox run <pkg>' once online to re-provision")

    print()
    print("  everything looks healthy" if ok else "  some checks FAILED - fix the items above")
    return 0 if ok else 1


# ---------- signing ----------

def cmd_keygen(args) -> int:
    r = signing.keygen(args.name, args.publisher or args.name)
    print(f"Created key pair '{args.name}'")
    print(f"  private: {r['private']}   (keep this secret!)")
    print(f"  public:  {r['public']}   (share this with recipients)")
    print(f"  seal_public:  {r['seal_public']}   (recipients publish this for 'blackbox seal --to')")
    print(f"  seal_private: {r['seal_private']}   (place on machines that must open sealed secrets)")
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


# ---------- seal ----------

def _attach_member(pkg_path, name, blob: bytes):
    """Deterministically rewrite the package ZIP with one extra member."""
    import io
    import zipfile
    with zipfile.ZipFile(str(pkg_path)) as zf:
        members = {n: zf.read(n) for n in zf.namelist()}
    members[name] = blob
    buf = io.BytesIO()
    ordered = [k for k in fmt.MEMBER_ORDER if k in members] + sorted(set(members) - set(fmt.MEMBER_ORDER))
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for mname in ordered:
            deterministic.add_to_deterministic_zip(zf, mname, members[mname])
    with open(str(pkg_path), "wb") as f:
        f.write(buf.getvalue())


def cmd_seal(args) -> int:
    pkg_path = os.path.abspath(args.package)
    pairs = sealing.parse_secrets_file(args.secrets)
    payload = "\n".join(f"{k}={v}" for k, v in pairs).encode("utf-8")
    if args.key:
        pub_path = paths.home() / "keys" / f"{args.key}.seal.pub.pem"
        if not pub_path.is_file():
            raise BlackboxError(f"No sealing public key named '{args.key}'.",
                                try_hint="blackbox keygen <name>   # creates <name>.seal.pub.pem")
        pub_pem = pub_path.read_bytes()
    elif args.to:
        pub_pem = open(args.to, "rb").read()
    else:
        raise BlackboxError("Specify a recipient: --to <recipient.seal.pub.pem> or --key <name>.")
    blob = sealing.seal_bytes(payload, pub_pem)
    _attach_member(pkg_path, fmt.SECRETS, blob)
    print(f"SEALED  {len(pairs)} secret(s) into {pkg_path}")
    print(f"  recipient fingerprint: sha256:{sealing.recipient_fingerprint(pub_pem)}")
    print("  note: the package contents changed — re-run 'blackbox sign' if it was signed.")
    return 0


# ---------- explain ----------

def cmd_explain(args) -> int:
    pkg = reader.open_package(args.package)
    m = pkg.manifest
    p = m["permissions"]
    print(summarize(m))
    print("")
    print("At run time (dry-run; nothing executes):")
    print(f"  work dir:      <cwd>/{m['name']}-work  (input/ output/ _blackbox_tmp/)")
    for rp in p["filesystem"]["read"]:
        print(f"  readable:      {rp}  (manifest)")
    for wp in p["filesystem"]["write"]:
        print(f"  writable:      {wp}  (manifest)")
    print("  always read:   application + dependency layers, runtime, sandbox shim")
    print(f"  network:       {'enabled' if p['network']['enabled'] else 'disabled'}"
          + (f"; allowlist: {', '.join(p['network']['allow'])}" if p["network"]["allow"] else ""))
    if m.get("limits"):
        print(f"  limits:        {', '.join(f'{k}={v}' for k, v in sorted(m['limits'].items()))}")
    if m.get("entrypoints"):
        print(f"  subcommands:   {', '.join(sorted(m['entrypoints']))}  (blackbox run <pkg> --entry <name>)")
    if fmt.SECRETS in pkg.members:
        print("  sealed secrets: package carries an encrypted payload (needs the recipient seal key)")
    print(f"  signature:     {signing.verify_package(pkg)['state']}")
    print(f"  run with data: blackbox run {os.path.basename(str(args.package))} --data")
    return 0


# ---------- diff ----------

def _unpacked_app_files(pkg) -> dict:
    dest = tempfile.mkdtemp(prefix="bb-diff-")
    reader.unpack_all(pkg, dest)
    app = os.path.join(dest, "application")
    out = {}
    for dirpath, _dirs, files in os.walk(app):
        for fn in files:
            p = os.path.join(dirpath, fn)
            out[os.path.relpath(p, app)] = deterministic.sha256_file(p)
    return out


def cmd_diff(args) -> int:
    a = reader.open_package(args.package_a)
    b = reader.open_package(args.package_b)
    ma, mb = a.manifest, b.manifest
    print(f"A: {a.package_id()}")
    print(f"B: {b.package_id()}")
    print("")
    changed = False
    for k in ("name", "version", "runtime", "entrypoint", "interface", "limits"):
        if ma.get(k) != mb.get(k):
            print(f"~ {k}: {ma.get(k)}  ->  {mb.get(k)}")
            changed = True
    if ma["permissions"] != mb["permissions"]:
        print(f"~ permissions: {ma['permissions']}  ->  {mb['permissions']}")
        changed = True
    import yaml
    la = yaml.safe_load(a.members[fmt.LOCK].decode("utf-8")) or {"packages": []}
    lb = yaml.safe_load(b.members[fmt.LOCK].decode("utf-8")) or {"packages": []}
    va = {p["name"]: p["version"] for p in la.get("packages", [])}
    vb = {p["name"]: p["version"] for p in lb.get("packages", [])}
    added = sorted(set(vb) - set(va))
    removed = sorted(set(va) - set(vb))
    updated = sorted(k for k in set(va) & set(vb) if va[k] != vb[k])
    print("")
    print("Dependencies:")
    for n in added:
        print(f"  + {n} {vb[n]}")
    for n in removed:
        print(f"  - {n} {va[n]}")
    for n in updated:
        print(f"  ~ {n}: {va[n]} -> {vb[n]}")
    if not (added or removed or updated):
        print("  (identical)")
    print("")
    print("Layers:")
    lai = {l["kind"]: l["digest"] for l in json.loads(a.members[fmt.LAYERS_INDEX])["layers"]}
    lbi = {l["kind"]: l["digest"] for l in json.loads(b.members[fmt.LAYERS_INDEX])["layers"]}
    for kind in sorted(set(lai) | set(lbi)):
        same = lai.get(kind) == lbi.get(kind)
        print(f"  {'=' if same else '!'} {kind}: {'same' if same else 'changed'}")
        if not same:
            changed = True
    if lai.get("application") != lbi.get("application"):
        print("")
        print("Application file changes:")
        fa, fb = _unpacked_app_files(a), _unpacked_app_files(b)
        n = 0
        for name in sorted(set(fa) | set(fb)):
            if n >= 100:
                print("  … (truncated)")
                break
            if name not in fb:
                print(f"  + {name}")
                n += 1
            elif name not in fa:
                print(f"  - {name}")
                n += 1
            elif fa[name] != fb[name]:
                print(f"  ~ {name}")
                n += 1
        changed = True
    if not changed:
        print("")
        print("Packages are content-identical in every compared dimension.")
    return 0


# ---------- audit ----------

def cmd_audit(args) -> int:
    pkg = reader.open_package(args.package)
    dest = tempfile.mkdtemp(prefix="bb-audit-")
    reader.unpack_all(pkg, dest)
    app = os.path.join(dest, "application")
    url_re = re.compile(r"(?:https?|wss?)://[^\s'\"<>\\)]+")
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    secret_re = re.compile(r"(BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk_live_)")
    danger = {
        ".py": [r"\bos\.system\b", r"\bsubprocess\b", r"\beval\s*\(", r"\bexec\s*\(",
                r"\bsocket\.socket\b", r"__import__"],
        ".js": [r"\bchild_process\b", r"\beval\s*\(", r"\bnew Function\b",
                r"\bnet\.(connect|createConnection)\b"],
    }
    bin_ext = {".exe", ".dll", ".so", ".dylib", ".bin", ".node", ".pyd"}
    urls, ips, secrets_hits, execs, bins = set(), [], [], [], []
    files = 0
    for dirpath, _dirs, filenames in os.walk(app):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, app)
            files += 1
            ext = os.path.splitext(fn)[1].lower()
            if ext in bin_ext:
                bins.append(rel)
                continue
            try:
                text = open(p, encoding="utf-8", errors="ignore").read(500_000)
            except OSError:
                continue
            for u in url_re.findall(text):
                if len(urls) < 24:
                    urls.add(u.rstrip(".,;"))
            for ip in ip_re.findall(text):
                if ip != "0.0.0.0" and not ip.startswith(("127.", "255.")):
                    ips.append(f"{ip} ({rel})")
            if secret_re.search(text):
                secrets_hits.append(rel)
            for pat in danger.get(ext, []):
                if re.search(pat, text):
                    execs.append(f"{rel}: {pat.strip(chr(92)).strip(chr(92))}")
    print(f"AUDIT   {pkg.manifest['name']} {pkg.manifest['version']}  ({files} app files)")
    print(f"  signature:      {signing.verify_package(pkg)['state']}")
    print(f"  network:        {'enabled' if pkg.manifest['permissions']['network']['enabled'] else 'disabled'}"
          + (f", allow {', '.join(pkg.manifest['permissions']['network']['allow'])}"
             if pkg.manifest['permissions']['network']['allow'] else ""))
    if urls:
        print("  endpoints:")
        for u in sorted(urls):
            print(f"    {u}")
    if ips:
        print("  raw IPs:")
        for i in sorted(set(ips))[:12]:
            print(f"    {i}")
    if execs:
        print("  exec/spawn/eval surfaces:")
        for e in sorted(set(execs))[:24]:
            print(f"    {e}")
    if bins:
        print("  bundled binaries:")
        for b in bins[:24]:
            print(f"    {b}")
    if secrets_hits:
        print("  !! possible hardcoded secrets in:")
        for s in secrets_hits:
            print(f"    {s}")
    if not (urls or ips or execs or bins or secrets_hits):
        print("  nothing notable found (text-scanned; binaries are hashed, not decompiled)")
    print("  this is a static scan, not a security guarantee — review before trusting.")
    return 0


# ---------- gc ----------

def cmd_gc(args) -> int:
    home = paths.home()
    layers_dir = home / "layers"
    cas = CAS()
    refs = {}
    if layers_dir.is_dir():
        for d in layers_dir.iterdir():
            if d.is_dir() and d.name.startswith("sha256_"):
                refs[d.name[len("sha256_"):]] = d
    objects = {}
    base = os.path.join(cas.root, "sha256")
    for dirpath, _dirs, files in os.walk(base):
        for fn in files:
            objects[fn] = os.path.join(dirpath, fn)
    orphan_objs = sorted(set(objects) - set(refs))
    missing_objs = sorted(set(refs) - set(objects))
    stale_layers = []
    if args.older_than:
        cutoff = time.time() - args.older_than * 86400
        for hexd, d in refs.items():
            try:
                if os.path.getmtime(str(d)) < cutoff:
                    stale_layers.append((hexd, d))
            except OSError:
                pass
    freed = sum(os.path.getsize(objects[h]) for h in orphan_objs if h in objects)
    print(f"GC     {home}")
    print(f"  layers:           {len(refs)}")
    print(f"  objects:          {len(objects)}")
    print(f"  orphan objects:   {len(orphan_objs)} ({deterministic.human_size(freed)})")
    print(f"  missing objects:  {len(missing_objs)}")
    if args.older_than:
        print(f"  layers unused >{args.older_than}d: {len(stale_layers)}")
    if not args.apply:
        print("  dry-run: repeat with --apply to delete orphans/stale layers and tmp files")
        return 0
    for h in orphan_objs:
        try:
            os.unlink(objects[h])
        except OSError:
            pass
    for _hexd, d in stale_layers:
        shutil.rmtree(str(d), ignore_errors=True)
    tmp_dir = home / "tmp"
    if tmp_dir.is_dir():
        for child in tmp_dir.iterdir():
            if child.is_dir():
                shutil.rmtree(str(child), ignore_errors=True)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass
    print("  applied: orphans, stale layers and tmp files removed")
    return 0


# ---------- shell / dev ----------

def cmd_shell(args) -> int:
    pkg = reader.open_package(args.package)
    sig = signing.verify_package(pkg)
    work = args.work or os.path.join(os.getcwd(), f"{pkg.manifest['name']}-work")
    _consent_gate(pkg, sig, assume_yes=args.yes)
    data_dir = paths.home() / "data" / pkg.package_id() if args.data else None
    ctx = reader.prepare_run(pkg, work, data_dir=data_dir)
    rt = pkg.manifest["runtime"]["type"]
    if rt in ("python", "node"):
        argv = [ctx.runtime_exe, "-i"]
    else:
        argv = [os.environ.get("COMSPEC", "cmd.exe") if os.name == "nt" else "/bin/sh"]
    return runner.exec_interactive(ctx, argv_override=argv)


def cmd_dev(args) -> int:
    src = os.path.abspath(args.path)
    mpath = os.path.join(src, "blackbox.yaml")
    if not os.path.isfile(mpath):
        raise BlackboxError(f"No blackbox.yaml in {src}.",
                            try_hint="Create one ('blackbox init' shows the shape) or use 'blackbox pack'.")
    m = load_manifest(open(mpath, encoding="utf-8").read())
    rt = m["runtime"]
    from blackbox.runtime.providers import get_provider
    provider = get_provider(rt["type"])
    pin = None
    if rt["type"] == "node":
        lock_p = os.path.join(src, "blackbox.lock")
        if os.path.isfile(lock_p):
            import yaml
            rmeta = (yaml.safe_load(open(lock_p, encoding="utf-8")) or {}).get("runtime", {})
            pin = {k: rmeta[k] for k in ("version", "asset", "url", "sha256") if k in rmeta} or None
    runtime_exe = provider.ensure(rt["version"], rt["target"], pin=pin)
    work = os.path.join(src, f"{m['name']}-dev")
    from blackbox.runtime.runner import RunContext
    ctx = RunContext(m, app_dir=src,
                     site_dir=(src if rt["type"] == "node" else ""),
                     runtime_exe=runtime_exe, work_dir=work, triple=rt["target"])
    app_args = [a for a in (args.app_args or []) if a != "--"]
    print(f"BLACKBOX: dev mode — {m['name']} from source (deps come from the project's "
          f"node_modules/venv; 'blackbox pack' resolves them fully)")
    return runner.execute(ctx, app_args)


# ---------- service ----------

def _svc_dir():
    d = paths.home() / "services"
    d.mkdir(parents=True, exist_ok=True)
    return d


def cmd_service(args) -> int:
    sc = getattr(args, "service_cmd", None)
    if sc == "install":
        return _svc_install(args)
    if sc == "uninstall":
        return _svc_uninstall(args.name)
    if sc == "list":
        return _svc_list()
    if sc == "status":
        return _svc_status(args.name)
    raise BlackboxError("Unknown service subcommand.", try_hint="install | uninstall | list | status")


def _svc_install(args) -> int:
    pkg_path = os.path.abspath(args.package)
    pkg = reader.open_package(pkg_path)
    name = args.name
    d = _svc_dir()
    work = d / f"{name}-work"
    log = d / f"{name}.log"
    exe = shutil.which("blackbox") or sys.argv[0]
    extra = (" " + args.args) if getattr(args, "args", "") else ""
    if os.name == "nt":
        ps = d / f"{name}.ps1"
        ps.write_text(
            f"Set-Location \"{d}\"\n"
            "while ($true) {\n"
            f"  & \"{exe}\" run \"{pkg_path}\" --yes{extra} *>> \"{log}\"\n"
            "  Start-Sleep -Seconds 10\n"
            "}\n", encoding="utf-8")
        import winreg
        val = (f"powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden "
               f"-File \"{ps}\"")
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                              r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
            winreg.SetValueEx(k, f"blackbox-svc-{name}", 0, winreg.REG_SZ, val)
        print(f"SERVICE  '{name}' registered (starts at logon, restarts every 10s if it exits)")
        print(f"  launcher: {ps}")
        print(f"  log:      {log}")
        print("  note: this is user-level autostart; a true SYSTEM service needs admin ('sc create').")
    elif sys.platform == "darwin":
        agents = Path.home() / "Library" / "LaunchAgents"
        agents.mkdir(parents=True, exist_ok=True)
        plist = agents / f"blackbox.{name}.plist"
        plist.write_text(f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>blackbox.{name}</string>
  <key>ProgramArguments</key><array>
    <string>{exe}</string><string>run</string><string>{pkg_path}</string><string>--yes</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>WorkingDirectory</key><string>{work}</string>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict></plist>""", encoding="utf-8")
        subprocess.run(["launchctl", "load", str(plist)], check=False)
        print(f"SERVICE  '{name}' installed as a LaunchAgent (KeepAlive): {plist}")
    else:
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        unit_dir.mkdir(parents=True, exist_ok=True)
        unit = unit_dir / f"blackbox-{name}.service"
        unit.write_text(f"""[Unit]
Description=BLACKBOX appliance {pkg.manifest['name']} ({name})

[Service]
WorkingDirectory={work}
ExecStart={exe} run {pkg_path} --yes{extra}
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
""", encoding="utf-8")
        systemctl = shutil.which("systemctl")
        if systemctl:
            subprocess.run([systemctl, "--user", "daemon-reload"], check=False)
            r = subprocess.run([systemctl, "--user", "enable", "--now", f"blackbox-{name}.service"],
                               check=False, capture_output=True, text=True)
            if r.returncode != 0:
                print(f"  systemctl: {r.stderr.strip() or 'enable failed — start it with: '
                          f'systemctl --user start blackbox-{name}'}")
        else:
            print("  systemd user session not found — unit written; start it inside your user session.")
        print(f"SERVICE  '{name}' installed: {unit}")
        print(f"  log:     journalctl --user -u blackbox-{name}")
    return 0


def _svc_uninstall(name) -> int:
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.DeleteValue(k, f"blackbox-svc-{name}")
        except FileNotFoundError:
            print(f"  no registered service '{name}'")
        ps = _svc_dir() / f"{name}.ps1"
        if ps.is_file():
            ps.unlink()
        print(f"SERVICE  '{name}' unregistered (a running instance stops at next exit)")
    elif sys.platform == "darwin":
        plist = Path.home() / "Library" / "LaunchAgents" / f"blackbox.{name}.plist"
        if plist.is_file():
            subprocess.run(["launchctl", "unload", str(plist)], check=False)
            plist.unlink()
            print(f"SERVICE  '{name}' unloaded and removed")
        else:
            print(f"  no LaunchAgent for '{name}'")
    else:
        unit = Path.home() / ".config" / "systemd" / "user" / f"blackbox-{name}.service"
        systemctl = shutil.which("systemctl")
        if systemctl and unit.is_file():
            subprocess.run([systemctl, "--user", "disable", "--now", f"blackbox-{name}.service"],
                           check=False, capture_output=True)
        if unit.is_file():
            unit.unlink()
            if systemctl:
                subprocess.run([systemctl, "--user", "daemon-reload"], check=False)
            print(f"SERVICE  '{name}' removed")
        else:
            print(f"  no unit for '{name}'")
    return 0


def _svc_list() -> int:
    found = False
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Run") as k:
                i = 0
                while True:
                    try:
                        val, _v, _t = winreg.EnumValue(k, i)
                        i += 1
                        if val.startswith("blackbox-svc-"):
                            print(f"  {val[len('blackbox-svc-'):]}")
                            found = True
                    except OSError:
                        break
        except FileNotFoundError:
            pass
    else:
        if sys.platform == "darwin":
            g = Path.home() / "Library" / "LaunchAgents"
            if g.is_dir():
                for p in sorted(g.glob("blackbox.*.plist")):
                    print(f"  {p.stem.split('.', 1)[1]}")
                    found = True
        else:
            g = Path.home() / ".config" / "systemd" / "user"
            if g.is_dir():
                for p in sorted(g.glob("blackbox-*.service")):
                    print(f"  {p.stem[len('blackbox-'):-len('.service')] if p.stem.endswith('.service') else p.stem[len('blackbox-'):]}")
                    found = True
    if not found:
        print("  no services installed")
    return 0


def _svc_status(name) -> int:
    log = _svc_dir() / f"{name}.log"
    if log.is_file():
        print(f"--- last lines of {log} ---")
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
        for ln in lines[-12:]:
            print(f"  {ln}")
    else:
        print(f"  no log yet for '{name}'")
    return 0


# ---------- upgrade (self-update channel) ----------

def cmd_upgrade(args) -> int:
    import urllib.request
    cur_path = os.path.abspath(args.package)
    cur = reader.open_package(cur_path)
    src = args.from_url
    tmp = tempfile.mkdtemp(prefix="bb-upgrade-")
    cand_path = os.path.join(tmp, "candidate.blackbox")
    if re.match(r"^https?://", src):
        print(f"BLACKBOX: downloading candidate from {src} ...")
        with urllib.request.urlopen(src, timeout=120) as r, open(cand_path, "wb") as f:
            f.write(r.read())
    else:
        if not os.path.isfile(src):
            raise BlackboxError(f"Upgrade source not found: {src}")
        shutil.copyfile(src, cand_path)
    cand = reader.open_package(cand_path)  # checksums verified on open
    if cand.manifest["name"] != cur.manifest["name"]:
        raise BlackboxError(
            "Refusing upgrade: candidate is a different package "
            f"('{cand.manifest['name']}' vs '{cur.manifest['name']}').")
    sig = signing.verify_package(cand)
    if sig["state"] == "invalid":
        raise BlackboxError("Refusing upgrade: candidate signature is INVALID.",
                            detail=sig.get("reason", ""))
    if sig["state"] == "unsigned":
        raise BlackboxError("Refusing upgrade: candidate is unsigned.",
                            try_hint="Publishers must sign updates: blackbox sign <pkg> --key <name>")
    if sig["state"] == "valid" and not args.yes:
        raise BlackboxError(
            f"Candidate is signed by '{sig['publisher']}', who is not in your trust store.",
            try_hint="blackbox trust <publisher.pub.pem> --publisher '<publisher>'  "
                     "or re-run with --yes to accept this specific update.")
    backup = cur_path + ".bak"
    if os.path.exists(backup):
        os.unlink(backup)
    os.replace(cur_path, backup)
    try:
        shutil.copyfile(cand_path, cur_path)
        check = reader.open_package(cur_path)
        assert check.content_digest == cand.content_digest
    except Exception:
        if os.path.exists(backup):
            os.replace(backup, cur_path)
        raise BlackboxError("Upgrade verification failed after swap — rolled back.")
    print(f"UPGRADE  {cur.manifest['name']}: {cur.manifest['version']} -> {cand.manifest['version']}")
    print(f"  publisher: {sig['publisher']} ({sig['state']})")
    print(f"  previous package kept as {backup}")
    return 0


# ---------- install / export-docker / bench ----------

def cmd_install(args) -> int:
    exe = shutil.which("blackbox") or sys.argv[0]
    if os.name == "nt":
        if not args.no_assoc:
            import winreg
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Classes\.blackbox") as k:
                winreg.SetValueEx(k, None, 0, winreg.REG_SZ, "Blackbox.Package")
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                                  r"Software\Classes\Blackbox.Package\shell\open\command") as k:
                winreg.SetValueEx(k, None, 0, winreg.REG_SZ, f"\"{exe}\" run \"%1\"")
            print("ASSOC    .blackbox double-click -> 'blackbox run' (user-level)")
        if args.package:
            pkg = reader.open_package(args.package)
            sm = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) \
                / "Microsoft" / "Windows" / "Start Menu" / "Programs"
            sm.mkdir(parents=True, exist_ok=True)
            lnk = sm / f"Blackbox {pkg.manifest['name']}.lnk"
            ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}');"
                  f"$s.TargetPath='{exe}';"
                  f"$s.Arguments='run \"{os.path.abspath(args.package)}\"';"
                  f"$s.Save()")
            subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           check=True, capture_output=True)
            print(f"SHORTCUT {lnk}")
    elif sys.platform.startswith("linux"):
        if args.package:
            pkg = reader.open_package(args.package)
            apps = Path.home() / ".local" / "share" / "applications"
            apps.mkdir(parents=True, exist_ok=True)
            desk = apps / f"blackbox-{pkg.manifest['name']}.desktop"
            desk.write_text(f"""[Desktop Entry]
Type=Application
Name=Blackbox {pkg.manifest['name']}
Exec={exe} run {os.path.abspath(args.package)}
Terminal=true
NoDisplay=false
""", encoding="utf-8")
            print(f"DESKTOP  {desk}")
        else:
            print("  give a package path to create a launcher; .blackbox mime assoc needs xdg-mime (not done)")
    else:
        print("  shortcuts are Windows/Linux only; run packages with 'blackbox run <pkg>'.")
    return 0


def cmd_export_docker(args) -> int:
    pkg = reader.open_package(args.package)
    m = pkg.manifest
    out = os.path.abspath(args.out or f"{m['name']}-docker")
    os.makedirs(out, exist_ok=True)
    reader.unpack_all(pkg, out)
    import yaml
    lock = yaml.safe_load(pkg.members[fmt.LOCK].decode("utf-8")) or {}
    pkgs = lock.get("packages", [])
    rt = m["runtime"]
    entry = m["entrypoint"]
    lines = ["# generated by 'blackbox export-docker' — review before building"]
    if rt["type"] == "python":
        major = ".".join(rt["version"].split(".")[:2]) or "3.12"
        lines += [f"FROM python:{major}-slim", "WORKDIR /app", "COPY application/ /app/"]
        if pkgs:
            pins = " ".join(f"{p['name']}=={p['version']}" for p in pkgs)
            lines.append(f"RUN pip install --no-cache-dir {pins}")
        lines.append("CMD [" + ", ".join(json.dumps(a) for a in (["python"] + entry["args"])) + "]")
    elif rt["type"] == "node":
        deps = {p["name"]: p["version"] for p in pkgs}
        (Path(out) / "package.json").write_text(
            json.dumps({"name": m["name"], "private": True, "dependencies": deps}, indent=2),
            encoding="utf-8")
        lines += [f"FROM node:{rt['version']}-slim", "WORKDIR /app",
                  "COPY application/ /app/", "COPY package.json /app/package.json",
                  "RUN npm install --omit=dev --no-audit --no-fund",
                  "CMD [" + ", ".join(json.dumps(a) for a in (["node"] + entry["args"])) + "]"]
    else:
        lines += ["FROM alpine:3", "COPY application/ /app/",
                  "ENTRYPOINT [\"/app" + entry["command"][1:] + "\"]"]
    lines.append("USER nobody")
    (Path(out) / "Dockerfile").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (Path(out) / ".dockerignore").write_text("dependencies/\nblackbox.lock\nchecksums.json\n", encoding="utf-8")
    print(f"DOCKER   wrote {Path(out) / 'Dockerfile'}  (context: {out})")
    print("  build: docker build -t " + m['name'] + " " + out)
    print("  note: container isolation replaces the BLACKBOX sandbox; permissions are not re-enforced inside.")
    return 0


def cmd_bench(args) -> int:
    pkg = reader.open_package(args.package)
    results = {}
    old_home = os.environ.get("BLACKBOX_HOME")
    cold_home = tempfile.mkdtemp(prefix="bb-bench-cold-")
    os.environ["BLACKBOX_HOME"] = cold_home
    t0 = time.perf_counter()
    reader.prepare_run(pkg, tempfile.mkdtemp(prefix="bb-bench-work-"))
    results["cold_prepare_s"] = time.perf_counter() - t0
    if old_home is None:
        os.environ.pop("BLACKBOX_HOME", None)
    else:
        os.environ["BLACKBOX_HOME"] = old_home
    t0 = time.perf_counter()
    ctx = reader.prepare_run(pkg, tempfile.mkdtemp(prefix="bb-bench-warm-"))
    results["warm_prepare_s"] = time.perf_counter() - t0
    t0 = time.perf_counter()
    runner.execute(ctx, quiet=True)
    results["app_run_s"] = time.perf_counter() - t0
    print(f"BENCH   {pkg.manifest['name']} {pkg.manifest['version']}")
    for k, v in results.items():
        print(f"  {k:<16} {v:8.3f}s")
    print(f"  cold home:        {cold_home}")
    return 0
