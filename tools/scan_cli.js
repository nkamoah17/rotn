// Find how the CLI treats the --header option and how it sends gateway requests.
const fs = require("fs");
const src = fs.readFileSync(
  process.env.APPDATA + "\\npm\\node_modules\\@aws\\agentcore\\dist\\index.js",
  "utf8"
);
function show(re, label, max = 12) {
  let n = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(src)) !== null && n < max) {
    const i = m.index;
    console.log("==== " + label + " @" + i + " ====");
    console.log(src.slice(Math.max(0, i - 200), i + 300).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/headers?\s*[:=]\s*\{[^}]{0,120}/gi, "header-obj");
show(/\bheader\b.{0,60}(join|push|forEach|map)/gi, "header-iter");
show(/["'](x-amzn|authorization|content-type)["']/gi, "hdr-names");
show(/gateway[^;{}]{0,80}(invoke|request|fetch)/gi, "gw-invoke");
show(/\bmethod\b\s*[:=]\s*["']POST["']/gi, "post");

