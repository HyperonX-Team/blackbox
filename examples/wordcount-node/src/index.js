const fs = require("fs");
const path = require("path");
const argv = require("minimist")(process.argv.slice(2));
const input = process.env.BLACKBOX_INPUT || path.join(process.cwd(), "input");
const output = process.env.BLACKBOX_OUTPUT || path.join(process.cwd(), "output");
const file = path.join(input, argv.file || "text.txt");
const counts = {};
for (const w of fs.readFileSync(file, "utf8").toLowerCase().split(/\W+/)) {
  if (w) counts[w] = (counts[w] || 0) + 1;
}
const top = Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 10);
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(path.join(output, "words.json"), JSON.stringify(Object.fromEntries(top), null, 2) + "\n");
console.log("node", process.version, "minimist ok");
for (const [w, n] of top) console.log(String(n).padStart(4), w);
