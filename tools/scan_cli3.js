// Find the commander option definition for --header and how its value is used.
const fs = require("fs");
const src = fs.readFileSync(
  process.env.APPDATA + "\\npm\\node_modules\\@aws\\agentcore\\dist\\main.js",
  "utf8"
);
function show(re, label, max = 8) {
  let n = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(src)) !== null && n < max) {
    const i = m.index;
    console.log("==== " + label + " @" + i + " ====");
    console.log(src.slice(Math.max(0, i - 300), i + 400).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/header\.\.\.[^"]{0,80}/g, "variadic", 6);
show(/["']--header["']/g, "opt", 6);
show(/an ordered application header/g, "help-text", 4);
