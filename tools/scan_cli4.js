// Find where the header array is consumed/parsed (Name: value split).
const fs = require("fs");
const src = fs.readFileSync(
  process.env.APPDATA + "\\npm\\node_modules\\@aws\\agentcore\\dist\\main.js",
  "utf8"
);
function show(re, label, max = 10) {
  let n = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(src)) !== null && n < max) {
    const i = m.index;
    console.log("==== " + label + " @" + i + " ====");
    console.log(src.slice(Math.max(0, i - 350), i + 450).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/\bheaders\b.{0,120}map\(/g, "map", 8);
show(/\bheaders\b.{0,120}split/g, "split", 8);
show(/parseHeader|headerToEntry|toHeaders|buildHeaders/g, "fn", 8);
show(/header.{0,60}indexOf\(":"\)/g, "idx", 8);
show(/\bheader\b.{0,80}trim\(\)/g, "trim", 8);
