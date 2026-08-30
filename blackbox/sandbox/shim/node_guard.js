"use strict";

// BLACKBOX runtime sandbox shim for Node.js.
// Loaded via NODE_OPTIONS=--require <this-file>. It reads the policy JSON
// from BLACKBOX_SANDBOX_POLICY and enforces network, spawn, and filesystem
// write restrictions in-process. This is defense-in-depth alongside any
// platform jail; it is not a kernel boundary on its own.

const fs = require("fs");
const net = require("net");
const path = require("path");

const LOOPBACK = new Set(["127.0.0.1", "::1", "localhost"]);

const policyPath = process.env.BLACKBOX_SANDBOX_POLICY;
let POLICY = { network: false, spawn: false, read_allowed: [], write_allowed: [], enforce: true };

if (policyPath && fs.existsSync(policyPath)) {
    try {
        Object.assign(POLICY, JSON.parse(fs.readFileSync(policyPath, "utf8")));
    } catch (_e) {
        // keep defaults
    }
}

function violation(kind, target, hint) {
    const msg =
        "\nBLACKBOX SANDBOX VIOLATION\n" +
        `  This package attempted ${kind} which its manifest does not permit:\n` +
        `    ${target}\n` +
        `  ${hint}\n`;
    process.stderr.write(msg);
    process.exit(76);
}

function allowed(target, roots) {
    const real = path.resolve(String(target));
    return roots.some(r => real === r || real.startsWith(r + path.sep));
}

// ---------- network ----------
function checkHost(host) {
    if (!POLICY.network && !LOOPBACK.has(String(host))) {
        violation("outbound network access", host,
            "Enable it in blackbox.yaml under permissions.network.enabled and re-pack.");
    }
}

const origConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function (...args) {
    let options = args[0];
    if (typeof options === "string") {
        return origConnect.call(this, ...args);
    }
    if (options && (options.host || options.hostname || options.port)) {
        checkHost(options.host || options.hostname || "<unknown>");
    }
    return origConnect.call(this, ...args);
};

const origCreateConnection = net.createConnection;
net.createConnection = function (...args) {
    let options = args[0];
    if (typeof options === "string") {
        return origCreateConnection.call(this, ...args);
    }
    if (options && (options.host || options.hostname)) {
        checkHost(options.host || options.hostname);
    }
    return origCreateConnection.call(this, ...args);
};

// ---------- process spawning ----------
const child = require("child_process");
function guardSpawn(cmd) {
    if (!POLICY.spawn && POLICY.enforce) {
        violation("process spawning", cmd,
            "Enable it in blackbox.yaml under permissions.process.spawn and re-pack.");
    }
}

const spawnFns = ["spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "fork"];
for (const name of spawnFns) {
    const orig = child[name];
    if (typeof orig !== "function") continue;
    child[name] = function (...args) {
        guardSpawn(String(args[0] || name));
        return orig.apply(this, args);
    };
}

// ---------- filesystem writes ----------
function isWriting(flags) {
    if (typeof flags === "number") {
        const O_WRONLY = require("fs").constants.O_WRONLY || 0x001;
        const O_RDWR = require("fs").constants.O_RDWR || 0x002;
        const O_CREAT = require("fs").constants.O_CREAT || 0x040;
        const O_TRUNC = require("fs").constants.O_TRUNC || 0x200;
        const O_APPEND = require("fs").constants.O_APPEND || 0x400;
        return (flags & O_WRONLY) !== 0 || (flags & O_RDWR) !== 0 ||
               (flags & O_CREAT) !== 0 || (flags & O_TRUNC) !== 0 || (flags & O_APPEND) !== 0;
    }
    if (typeof flags !== "string" || flags === "") return false;
    return /[wax+]/.test(flags);
}

function checkWrite(target) {
    if (!POLICY.enforce || !target) return;
    const resolved = path.resolve(String(target));
    if (!allowed(resolved, POLICY.write_allowed)) {
        violation("filesystem write", resolved,
            "Add this path to permissions.filesystem.write (relative to the package) and re-pack.");
    }
}

const blockingFns = [
    ["writeFileSync", 0],
    ["appendFileSync", 0],
];
for (const [name, idx] of blockingFns) {
    const orig = fs[name];
    if (typeof orig !== "function") continue;
    fs[name] = function (...args) {
        if (args[idx] !== undefined) checkWrite(args[idx]);
        return orig.apply(this, args);
    };
}

const origOpen = fs.open;
fs.open = function (target, flags, ...rest) {
    if (isWriting(flags)) checkWrite(target);
    return origOpen.call(this, target, flags, ...rest);
};

const origOpenSync = fs.openSync;
fs.openSync = function (target, flags, ...rest) {
    if (isWriting(flags)) checkWrite(target);
    return origOpenSync.call(this, target, flags, ...rest);
};

const origWriteStream = fs.createWriteStream;
fs.createWriteStream = function (target, options) {
    const mode = (options && options.flags) || "w";
    if (isWriting(mode)) checkWrite(target);
    return origWriteStream.call(this, target, options);
};

// ---------- read restriction (best-effort when platform jail is absent) ----------
const origReadStream = fs.createReadStream;
fs.createReadStream = function (target, options) {
    if (POLICY.enforce && target) {
        const resolved = path.resolve(String(target));
        if (!allowed(resolved, POLICY.read_allowed)) {
            violation("filesystem read outside allowlist", resolved,
                "Add this path to permissions.filesystem.read (relative to the package) and re-pack.");
        }
    }
    return origReadStream.call(this, target, options);
};
