const fs = require("fs");
const os = require("os");
const path = require("path");

console.log("Hello from inside a BLACKBOX!");
console.log("  node:     " + process.version);
console.log("  platform: " + process.platform + "/" + process.arch);
console.log("  work dir: " + (process.env.BLACKBOX_WORK || process.cwd()));

const out = process.env.BLACKBOX_OUTPUT;
if (out) {
  const p = path.join(out, "hello.txt");
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(p, "written from inside a BLACKBOX (node)\n");
  console.log("  wrote:    " + p);
}
