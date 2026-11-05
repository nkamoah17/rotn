// Find how the CLI treats the --header option (real bundle: dist/main.js).
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
    console.log(src.slice(Math.max(0, i - 250), i + 350).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/--header/g, "flag", 6);
show(/headers?\s*[:=]\s*\{[^}]{0,140}/gi, "header-obj", 8);
show(/\bheader\b.{0,80}(join|push|forEach|map|split)/gi, "header-iter", 8);
show(/[\"'](x-amzn|authorization)[\"']/gi, "hdr-names", 8);
