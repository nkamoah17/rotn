// Find normalizeGatewayInvokeRequest definition + gateway URL construction.
const fs = require("fs");
const src = fs.readFileSync(
  process.env.APPDATA + "\\npm\\node_modules\\@aws\\agentcore\\dist\\main.js",
  "utf8"
);
function show(label, needle, before = 100, after = 1400) {
  const i = src.indexOf(needle);
  if (i < 0) { console.log("== " + label + ": NOT FOUND =="); return; }
  console.log("== " + label + " @" + i + " ==");
  console.log(src.slice(Math.max(0, i - before), i + after).replace(/\n/g, "\\n"));
}
show("normalize", "function normalizeGatewayInvokeRequest", 0, 1600);
show("url-pattern", ".gateway.bedrock-agentcore", 200, 400);
show("url-pattern2", "gateway.", 0, 0);

