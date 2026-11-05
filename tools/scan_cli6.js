// Show the core invokeGateway implementation (endpoint, signing, headers).
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
    console.log(src.slice(Math.max(0, i - 400), i + 1000).replace(/\n/g, "\\n"));
    n++;
  }
  if (!n) console.log("==== " + label + ": (none) ====");
}
show(/invokeGateway\s*[=(]/g, "impl", 6);
show(/gateway\.bedrock-agentcore/g, "host", 4);
