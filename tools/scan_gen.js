// Find the policy-generation CLI command (prompt -> Cedar).
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
    console.log(src.slice(Math.max(0, i - 400), i + 600).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/generatePolicy|GeneratePolicy/g, "gen-fn", 8);
show(/policy.{0,20}generate|generate.{0,20}policy/gi, "gen-cmd", 8);
show(/name:"generate"/g, "gen-name", 6);
